from ryu.lib.packet import packet, tcp, ethernet, ipv4
from ryu.lib import hub
import logging
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
import threading

class Node(object):
    def __init__(self, name, ip, port, domain, **kwargs):
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
        self.type = None
        self.domain = domain
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
            'port': self.port,
            'domain': self.domain
        }

    def setHandoverCallback(self, fn):
        return

    def setPortInformation(self, datapath_id, port_id):
        self.datapath_id = datapath_id
        self.port_id = port_id


class ServiceEngine(Node):
    def __init__(self, **kwargs):
        self.sessions = []
        self.garbageLoop = hub.spawn_after(1, self._garbageCollector)
        super(ServiceEngine, self).__init__(**kwargs)
        self.type = 'se'
        self.handover = None

    def __str__(self):
        return 'Service Engine node. HTTP engine on {}:{:d}'.format(self.ip, self.port) + \
            '. Attached to Access Switch {} port id {:d}'.format(self.datapath_id, self.port_id) if self.datapath_id else ''

    def __eq__(self, other):
        return isinstance(other, ServiceEngine) and \
               self.name == other.name and \
               self.ip == other.ip and \
               self.port == other.port

    def setHandoverCallback(self, fn):
        self.handover = fn

    def _performHandover(self, sess):
        self.handover(sess)

    def _garbageCollector(self):
        for sess in self.sessions:  # type: TCPSesssion
            if sess.state in [TCPSesssion.STATE_CLOSED, TCPSesssion.STATE_TIMEOUT, TCPSesssion.STATE_CLOSED_RESET]:
                self.logger.info('Removing finished session ' + str(sess))
                self.sessions.remove(sess)

        self.garbageLoop = hub.spawn_after(1, self._garbageCollector)

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
        for sess in self.sessions: #type: TCPSesssion
            if sess.ip.src == ip.src and \
                    sess.ip.dst == ip.dst and \
                    sess.ptcp.src_port == ptcp.src_port and \
                    sess.ptcp.dst_port == ptcp.dst_port:
                pkt = sess.handlePacket(pkt, eth, ip, ptcp)
                self.logger.debug(str(sess))
                return pkt
            if sess.ip.dst == ip.src and \
                    sess.ip.src == ip.dst and \
                    sess.ptcp.src_port == ptcp.dst_port and \
                    sess.ptcp.dst_port == ptcp.src_port:
                pkt = sess.handlePacket(pkt, eth, ip, ptcp)
                self.logger.debug(str(sess))

                if (sess.handoverReady):
                    self.logger.info('Handover is ready on SE too. Requesting CNT to do the dirty stuff')
                    self._performHandover(sess)
                return pkt

        # Create a new TCP session if the existin session is not found
        if ptcp.bits & tcp.TCP_SYN:
            sess = TCPSesssion(pkt, eth, ip, ptcp, self)
            self.sessions.append(sess)
        else:
            self.logger.error('Unexpected non SYN packet arrived to processing')
        return pkt


class RequestRouter(Node):
    def __init__(self, **kwargs):
        self.handoverSessions = []
        self.garbageLoop = hub.spawn_after(1, self._garbageCollector)
        super(RequestRouter, self).__init__(**kwargs)
        self.type = 'rr'
        self.getSe = None

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
        """

        :param sess:
        :type sess: HandoverSession
        :return:
        """
        if not sess.serviceEngine:
            se = self.getSe(sess.ip.src)
            if se:
                sess.serviceEngine = se
                sess.event.set()
            else:
                self.logger.error('Failed to find suitable Service engine for session ' + str(sess))

    def setHandoverCallback(self, fn):
        self.getSe = fn

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

        for sess in self.handoverSessions: #type: HandoverSession
            if sess.ip.src == ip.src and \
                    sess.ip.dst == ip.dst and \
                    sess.ptcp.src_port == ptcp.src_port and \
                    sess.ptcp.dst_port == ptcp.dst_port:
                pkt = sess.handlePacket(pkt, eth, ip, ptcp)
                self.logger.debug(str(sess))
                return pkt
            if sess.ip.dst == ip.src and \
                    sess.ip.src == ip.dst and \
                    sess.ptcp.src_port == ptcp.dst_port and \
                    sess.ptcp.dst_port == ptcp.src_port:
                pkt = sess.handlePacket(pkt, eth, ip, ptcp)

                if sess.handoverReady:
                    self.logger.info('Starting handover for ' + str(sess))
                    self._performHandover(sess)
                return pkt

        # Create a new TCP session if the existin session is not found
        if ptcp.bits & tcp.TCP_SYN:
            sess = HandoverSession(pkt, eth, ip, ptcp, self)
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

    def __init__(self, pkt, eth, ip, ptcp, parentNode):
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
        self.dst_seq = None

        self.timeoutTimer = hub.spawn_after(self.TIMEOUT_TIMER, self._handleTimeout)
        self.quietTimer = None
        self.garbageTimer = None

        self.request_size = 0
        self.handoverReady = False
        self.handoverRequested = False
        self.handoverPair = None
        self.parentNode = parentNode

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

    def _processPayload(self):
        if self.upstream_payload.strip() == "":
            self.logger.info('Payload is empty line, not parsing')
        else:
            self.httpRequest = HttpRequest(self.upstream_payload)
            if self.httpRequest.error_code:
                self.logger.error('failed to parse HTTP request')
            else:
                self.logger.info('payload parsed')
                self.logger.info(self.httpRequest.raw_requestline)
                self.request_size = len(self.upstream_payload)
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
                        self.logger.debug('Retransmission occured for ' + str(self))
                    elif ptcp.bits & tcp.TCP_RST:
                        self._handleReset()
                elif self.server_state == self.SERVER_STATE_SYN_RCVD:
                    if ptcp.bits & tcp.TCP_SYN:
                        self.logger.debug('Retransmission from client occurred for ' + str(self))
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
                            self.logger.debug('Going to state SYN / ACK. Waiting for ACK to establish session ' + str(self))
                            self.server_state = self.SERVER_STATE_SYN_RCVD
                            self.dst_seq = ptcp.seq
                        else:
                            self.logger.debug('Retransmission from server occurred on SYN_ACK' + str(self))

        elif self.state == self.STATE_ESTABLISHED:
            if from_client:
                if ptcp.bits & tcp.TCP_FIN:
                    self.state = self.STATE_CLOSING
                    self._handleClosing(ptcp.bits, from_client, pload, ptcp.seq, ptcp.ack)
                elif ptcp.bits & tcp.TCP_RST:
                    self._handleReset()
                elif ptcp.bits & tcp.TCP_PSH:
                    if pload:
                        self.upstream_payload +=pload
                        self._processPayload()
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
    def __init__(self, pkt, eth, ip, ptcp, parentNode):
        self.serviceEngine = None
        self.event = threading.Event()
        super(HandoverSession, self).__init__(pkt, eth, ip, ptcp, parentNode)

    def popDestinationSesssion(self):
        if not self.serviceEngine:
            self.logger.error('serviceEngine is not set')
            return None
        for sess in self.serviceEngine.sessions:  # type: TCPSesssion
            if sess.state == TCPSesssion.STATE_ESTABLISHED and not sess.handoverRequested:
                sess.handoverRequested = True
                # Set pointers to each other for faster handover manipulation
                self.handoverPair = sess
                sess.handoverPair = self
                return sess
        return None

    def __str__(self):
        return "Session from " + self.ip.src + ':' + str(self.ptcp.src_port) + \
               ' to ' + self.ip.dst + ':' + str(self.ptcp.dst_port) + ' in state ' + self.state if not self.serviceEngine else "Session from " + self.ip.src + ':' + str(self.ptcp.src_port) + \
               ' to ' + self.ip.dst + ':' + str(self.ptcp.dst_port) + ' in state ' + self.state + ' SE attached ' + str(self.serviceEngine)



class HttpRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        try:
            self.parse_request()
        except:
            self.error_code = 400