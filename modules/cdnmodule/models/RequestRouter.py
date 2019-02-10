from modules.cdnmodule.models.node import Node
from modules.cdnmodule.models.TCPSession import TCPSesssion
from modules.cdnmodule.models.HandoverSesssion import HandoverSession

from ryu.lib import hub
from ryu.lib.packet import packet, tcp, ethernet, ipv4

from eventlet.semaphore import Semaphore

class RequestRouter(Node):
    def __init__(self, **kwargs):
        self.handoverSessions = []
        self.garbageLoop = hub.spawn_after(1, self._garbageCollector)
        super(RequestRouter, self).__init__(**kwargs)
        self.type = 'rr'
        self.getSe = None
        self.lock = Semaphore()

    def __str__(self):
        return 'Request Router node. HTTP engine on {}:{:d}'.format(self.ip, self.port) + \
            '. Attached to Access Switch {} port id {:d}'.format(self.datapath_id, self.port_id) if self.datapath_id else ''

    def __eq__(self, other):
        return isinstance(other, RequestRouter) and \
               self.name == other.name and \
               self.ip == other.ip and \
               self.port == other.port

    def _garbageCollector(self):
        self.lock.acquire()

        for sess in self.handoverSessions[:]:  # type: HandoverSession
            if sess.state in [TCPSesssion.STATE_CLOSED, TCPSesssion.STATE_TIMEOUT, TCPSesssion.STATE_CLOSED_RESET, TCPSesssion.STATE_HANDOVERED]:
                self.logger.info('Removing finished session ' + str(sess))
                self.handoverSessions.remove(sess)

        self.lock.release()
        self.garbageLoop = hub.spawn_after(1, self._garbageCollector)

    def _performHandover(self, sess):
        """

        :param sess:
        :type sess: HandoverSession
        :return:
        """
        self.logger.info('Performhandover is called from Request Router, we gonna find a service engine')
        if not sess.serviceEngine:
            se = self.getSe(sess.ip.src)
            if se:
                self.logger.info('we found se')
                sess.serviceEngine = se
                sess.event.set()
                self.mitigate(self.datapath_id, sess.ip.src, sess.ip.dst, sess.ptcp.src_port, sess.ptcp.dst_port)
                self.mitigate(self.datapath_id, sess.ip.dst, sess.ip.src, sess.ptcp.dst_port, sess.ptcp.src_port)
                self.logger.debug('Mitigating all corresponding communication from client to Request routed and vice versa')

                self.logger.info('Event was set')
                self.logger.info(se)
            else:
                self.logger.error('Failed to find suitable Service engine for session ' + str(sess))
        else:
            self.logger.info('service engine is set for session')
            self.logger.info(sess.event.is_set())

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
        self.lock.acquire()
        self.logger.info('currently available sessions:')
        for sess in self.handoverSessions: #type: HandoverSession
            self.logger.info(sess)
            if sess.ip.src == ip.src and \
                    sess.ip.dst == ip.dst and \
                    sess.ptcp.src_port == ptcp.src_port and \
                    sess.ptcp.dst_port == ptcp.dst_port:
                pkt = sess.handlePacket(pkt, eth, ip, ptcp)

                if sess.handoverReady:
                    self.logger.info('Preparing suitable SE for ' + str(sess))
                    self._performHandover(sess)

                self.lock.release()
                return pkt, None
            if sess.ip.dst == ip.src and \
                    sess.ip.src == ip.dst and \
                    sess.ptcp.src_port == ptcp.dst_port and \
                    sess.ptcp.dst_port == ptcp.src_port:
                pkt = sess.handlePacket(pkt, eth, ip, ptcp)
                self.lock.release()
                return pkt, None

        # Create a new TCP session if the existin session is not found
        if ptcp.bits & tcp.TCP_SYN:
            sess = HandoverSession(pkt, eth, ip, ptcp, self)
            self.handoverSessions.append(sess)
            self.lock.release()
            return pkt, None
        else:
            self.logger.error('Unexpected non SYN packet arrived to processing')

        self.logger.error("Packet went through pipeline without match in RR")
        self.lock.release()
        return pkt, None
