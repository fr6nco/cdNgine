from modules.cdnmodule.models.TCPSession import TCPSesssion
import threading

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
        self.logger.error('No suitable session found')
        self.logger.error('there are sessions available: ')
        for sess in self.serviceEngine.sessions:
            self.logger.error(sess)
            self.logger.error('requested?')
            self.logger.error(self.handoverRequested)
        return None

    def __str__(self):
        return "Session from " + self.ip.src + ':' + str(self.ptcp.src_port) + \
               ' to ' + self.ip.dst + ':' + str(self.ptcp.dst_port) + ' in state ' + self.state if not self.serviceEngine else "Session from " + self.ip.src + ':' + str(self.ptcp.src_port) + \
               ' to ' + self.ip.dst + ':' + str(self.ptcp.dst_port) + ' in state ' + self.state + ' SE attached ' + str(self.serviceEngine)

