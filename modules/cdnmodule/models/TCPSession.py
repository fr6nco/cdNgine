from ryu.lib import hub
from ryu.lib.packet import packet, tcp, ethernet, ipv4
import logging

from modules.cdnmodule.models.HTTPRequest import HttpRequest

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
        self.handovered = False
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