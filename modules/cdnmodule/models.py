from ryu.lib.packet import packet, tcp, ethernet, ipv4
from ryu.lib import hub
import logging
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

class Node(object):
    def __init__(self, name, ip, port, **kwargs):
        """
        Base class for node
        Factory pattern to generate different type of nodes
        :param name: name of node
        :param ip: ip address of http engine
        :param port: port address of http engine
        """
        self.name = name
        self.ip = ip
        self.port = port
        self.datapath_id = None
        self.port_id = None
        self.logger = logging.getLogger('Node')
        super(Node, self).__init__()

    def factory(**kwargs):
        if kwargs['type'] == 'se':
            return ServiceEngine(**kwargs)
        if kwargs['type'] == 'rr':
            return RequestRouter(**kwargs)

    factory = staticmethod(factory)

    def serialize(self):
        return {
            'type': self.type,
            'datapath_id': self.datapath_id,
            'port_id': self.port_id,
            'name': self.name,
            'ip': self.ip,
            'port': self.port
        }

    def setPortInformation(self, datapath_id, port_id):
        self.datapath_id = datapath_id
        self.port_id = port_id


class ServiceEngine(Node):
    def __init__(self, **kwargs):
        self.type = 'se'
        self.sessions = []
        super(ServiceEngine, self).__init__(**kwargs)

    def __str__(self):
        return 'Service Engine node. HTTP engine on {}:{:d}'.format(self.ip, self.port) + \
            '. Attached to Access Switch {} port id {:d}'.format(self.datapath_id, self.port_id) if self.datapath_id else ''

    def __eq__(self, other):
        return isinstance(other, ServiceEngine) and \
               self.name == other.name and \
               self.ip == other.ip and \
               self.port == other.port

    def handlePacket(self, pkt, eth, ip, tcp):
        pass


class RequestRouter(Node):
    def __init__(self, **kwargs):
        self.type = 'rr'
        self.handoverSessions = []
        self.garbageLoop = hub.spawn_after(1, self._garbageCollector)
        super(RequestRouter, self).__init__(**kwargs)

    def __str__(self):
        return 'Request Router node. HTTP engine on {}:{:d}'.format(self.ip, self.port) + \
            '. Attached to Access Switch {} port id {:d}'.format(self.datapath_id, self.port_id) if self.datapath_id else ''

    def __eq__(self, other):
        return isinstance(other, RequestRouter) and \
               self.name == other.name and \
               self.ip == other.ip and \
               self.port == other.port

    def _garbageCollector(self):
        for sess in self.handoverSessions:  # type: HandoverSession
            if sess.state in [TCPSesssion.STATE_CLOSED, TCPSesssion.STATE_TIMEOUT, TCPSesssion.STATE_CLOSED_RESET]:
                self.logger.info('Removing finished session ' + str(sess))
                self.handoverSessions.remove(sess)

        self.garbageLoop = hub.spawn_after(1, self._garbageCollector)

    def _performHandover(self, sess):
        pass

    def handlePacket(self, pkt, eth, ip, ptcp):
        """
        Handles packet and returns the packet. Packet might change

        :param pkt:
        :param eth:
        :type eth: ethernet.ethernet
        :param ip:
        :type ip: ipv4.ipv4
        :param ptcp:
        :type ptcp: tcp.tcp
        :return:
        """

        found = False
        for sess in self.handoverSessions: #type: HandoverSession
            if sess.ip.src == ip.src and \
                    sess.ip.dst == ip.dst and \
                    sess.ptcp.src_port == ptcp.src_port and \
                    sess.ptcp.dst_port == ptcp.dst_port:
                pkt = sess.handlePacket(pkt, eth, ip, ptcp)
                self.logger.info(str(sess))
                return pkt
            if sess.ip.dst == ip.src and \
                    sess.ip.src == ip.dst and \
                    sess.ptcp.src_port == ptcp.dst_port and \
                    sess.ptcp.dst_port == ptcp.src_port:
                pkt = sess.handlePacket(pkt, eth, ip, ptcp)
                self.logger.info(str(sess))

                if sess.handoverReady:
                    self.logger.info('Starting handover for ' + str(sess))
                    self._performHandover(sess)
                return pkt

        # Create a new TCP session if the existin session is not found
        if ptcp.bits & tcp.TCP_SYN:
            sess = HandoverSession(pkt, eth, ip, ptcp)
            self.handoverSessions.append(sess)
        else:
            self.logger.error('Unexpected non SYN packet arrived to processing')
        return pkt



class TCPSesssion(object):
    STATE_OPENING = 'opening'
    STATE_ESTABLISHED = 'established'
    STATE_CLOSING = 'closing'
    STATE_TIME_WAIT = 'close_time_wait'

    STATE_TIMEOUT_TIME_WAIT = 'timeout_wait'
    STATE_TIMEOUT = "timeout"

    STATE_CLOSED_RESET_TIME_WAIT = "reset_wait"
    STATE_CLOSED_RESET = "reset"
    STATE_CLOSED = "closed"

    # SUBStates for endpoints
    CLIENT_STATE_SYN_SENT = "c_syn_sent"
    SERVER_STATE_SYN_RCVD = "s_syn_rcvd"

    CLOSING_FIN_SENT = "fin_sent"

    TIMEOUT_TIMER = 10
    QUIET_TIMER = 10
    RESET_TIMER = 1
    GARBAGE_TIMER = 30 + QUIET_TIMER  # This timer is used to handle problematic closes

    def __init__(self, pkt, eth, ip, ptcp):
        """

        :param pkt:
        :param eth:
        :type eth: ethernet.ethernet
        :param ip:
        :type ip: ipv4.ipv4
        :param ptcp:
        :type ptcp: tcp.tcp
        :return:
        """
        # MAIN STATES


        self.pkt_syn = pkt

        self.eth = eth
        self.ip = ip
        self.ptcp = ptcp
        self.state = self.STATE_OPENING
        self.client_state = self.CLIENT_STATE_SYN_SENT
        self.server_state = None
        self.src_seq = ptcp.seq

        self.timeoutTimer = hub.spawn_after(self.TIMEOUT_TIMER, self._handleTimeout)
        self.quietTimer = None
        self.garbageTimer = None

        self.handoverReady = False

        self.upstream_payload = ""

        self.logger = logging.getLogger('TCPSession')
        self.logger.info('New Session ' + str(self))

    def __str__(self):
        return "Session from " + self.ip.src + ':' + str(self.ptcp.src_port) + \
               ' to ' + self.ip.dst + ':' + str(self.ptcp.dst_port) + ' in state ' + self.state

    def _handleQuietTimerTimeout(self):
        self.logger.info('Quiet timer occured for ' + str(self))
        if self.state == self.STATE_TIME_WAIT:
            self.state = self.STATE_CLOSED
        elif self.state == self.STATE_TIMEOUT_TIME_WAIT:
            self.state = self.STATE_TIMEOUT
        elif self.state == self.STATE_CLOSED_RESET_TIME_WAIT:
            self.state = self.STATE_CLOSED_RESET
        self.quietTimer = None

    def _handleTimeout(self):
        self.logger.info('Timeout occured for ' + str(self))
        self.state = self.STATE_TIMEOUT_TIME_WAIT
        if self.quietTimer:
            self.quietTimer.cancel()
        self.quietTimer = hub.spawn_after(self.QUIET_TIMER, self._handleQuietTimerTimeout)

    def _handleReset(self):
        self.state = self.STATE_CLOSED_RESET_TIME_WAIT
        if self.timeoutTimer is not None:
            self.timeoutTimer.cancel()
        if self.quietTimer is not None:
            self.quietTimer.cancel()
        self.quietTimer = hub.spawn_after(self.RESET_TIMER, self._handleQuietTimerTimeout)

    def _handleGarbage(self):
        if self.STATE_ESTABLISHED not in [self.client_state, self.server_state]:
            self.logger.debug('Due to retransmission and bad packet ordering state did not close, ' \
                  'however none of the client/server is in established state. Closing and cleaning up garbage')
            self.state = self.STATE_CLOSED

    def _handleClosing(self, flags, from_client, p, seq, ack):
        if self.garbageTimer is None:
            self.garbageTimer = hub.spawn_after(self.GARBAGE_TIMER, self._handleGarbage)

        if flags & tcp.TCP_RST:
            self._handleReset()
            return

        if from_client:
            if flags & tcp.TCP_FIN:
                self.client_state = self.CLOSING_FIN_SENT
                self.client_fin_ack = seq + len(p) + 1 if p else seq + 1
            if self.server_state == self.CLOSING_FIN_SENT and ack == self.server_fin_ack and flags & tcp.TCP_ACK:
                self.server_state = self.STATE_CLOSED
                if self.client_state == self.STATE_CLOSED:
                    self.state = self.STATE_TIME_WAIT
        else:
            if flags & tcp.TCP_FIN:
                self.server_state = self.CLOSING_FIN_SENT
                self.server_fin_ack = seq + len(p) + 1 if p else seq + 1
            if self.client_state == self.CLOSING_FIN_SENT and ack == self.client_fin_ack and flags & tcp.TCP_ACK:
                self.client_state = self.STATE_CLOSED
                if self.server_state == self.STATE_CLOSED:
                    self.state = self.STATE_TIME_WAIT

    def _processPayload(self, p):
        self.upstream_payload += p
        if self.upstream_payload.strip() == "":
            self.logger.info('Payload is empty line, not parsing')
        else:
            self.httpRequest = HttpRequest(self.upstream_payload)
            if self.httpRequest.error_code:
                self.logger.error('failed to parse HTTP request')
            else:
                self.logger.info('payload parsed')
                self.logger.info(self.httpRequest.raw_requestline)
                self.reqeuest_size = len(self.upstream_payload)
                self.handoverReady = True
        self.upstream_payload = ""

    def handlePacket(self, pkt, eth, ip, ptcp):
        """
        TCP state diagram handling of packet
        :param pkt:
        :param eth:
        :param ip:
        :param ptcp:
        :return:
        """
        pload = None
        for protocol in pkt:
            if not hasattr(protocol, 'protocol_name'):
                pload = protocol # extracting payload

        from_client = True if ip.dst == self.ip.dst else False

        if self.state == self.STATE_OPENING:
            if from_client:
                if self.server_state is None:
                    if ptcp.bits & tcp.TCP_SYN:
                        self.logger.info('Retransmission occured for ' + str(self))
                    elif ptcp.bits & tcp.TCP_RST:
                        self._handleReset()
                elif self.server_state == self.SERVER_STATE_SYN_RCVD:
                    if ptcp.bits & tcp.TCP_SYN:
                        self.logger.info('Retransmission from client occurred for ' + str(self))
                    elif ptcp.bits & tcp.TCP_RST:
                        self._handleReset()
                    elif ptcp.bits & tcp.TCP_ACK:
                        self.logger.info('Transitioning to established state ' + str(self))
                        self.client_state = self.STATE_ESTABLISHED
                        self.server_state = self.STATE_ESTABLISHED
                        self.state = self.STATE_ESTABLISHED
                        self.timeoutTimer.cancel()
                        self.timeoutTimer = None
            else:
                if self.client_state == self.CLIENT_STATE_SYN_SENT:
                    if ptcp.bits & tcp.TCP_RST:
                        self._handleReset()
                    elif ptcp.bits & (tcp.TCP_SYN | tcp.TCP_ACK) == (tcp.TCP_SYN | tcp.TCP_ACK):
                        if self.server_state is None:
                            self.logger.info('Going to state SYN / ACK. Waiting for ACK to establish session ' + str(self))
                            self.server_state = self.SERVER_STATE_SYN_RCVD
                        else:
                            self.logger.info('Retransmission from server occurred on SYN_ACK' + str(self))

        elif self.state == self.STATE_ESTABLISHED:
            if from_client:
                if ptcp.bits & tcp.TCP_FIN:
                    self.state = self.STATE_CLOSING
                    self._handleClosing(ptcp.bits, from_client, pload, ptcp.seq, ptcp.ack)
                elif ptcp.bits & tcp.TCP_RST:
                    self._handleReset()
                elif ptcp.bits & tcp.TCP_PSH:
                    if pload:
                        self._processPayload(pload)
                elif ptcp.bits & tcp.TCP_ACK:
                    if pload is not None:
                        self.upstream_payload += pload
            else:
                if ptcp.bits & tcp.TCP_FIN:
                    self.state = self.STATE_CLOSING
                    self._handleClosing(ptcp.bits, from_client, pload, ptcp.seq, ptcp.ack)

        elif self.state == self.STATE_CLOSING:
            self._handleClosing(ptcp.bits, from_client, pload, ptcp.seq, ptcp.ack)
            if self.state == self.STATE_TIME_WAIT:
                self.garbageTimer.cancel()
                self.garbageTimer = None
                self.quietTimer = hub.spawn_after(self.QUIET_TIMER, self._handleQuietTimerTimeout)

        return pkt


class HandoverSession(TCPSesssion):
    def __init__(self, pkt, eth, ip, ptcp):
        super(HandoverSession, self).__init__(pkt, eth, ip, ptcp)


class HttpRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        try:
            self.parse_request()
        except:
            self.error_code = 400