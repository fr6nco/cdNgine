from modules.cdnmodule.models.node import Node
from modules.cdnmodule.models.TCPSession import TCPSesssion

from ryu.lib import hub
from ryu.lib.packet import packet, tcp, ethernet, ipv4
import threading

from eventlet.semaphore import Semaphore

class ServiceEngine(Node):
    def __init__(self, **kwargs):
        self.sessions = []
        self.garbageLoop = hub.spawn_after(1, self._garbageCollector)
        super(ServiceEngine, self).__init__(**kwargs)
        self.type = 'se'
        self.handover = None
        self.rsttcp = None
        self.lock = Semaphore()

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

    def setRSTCallback(self, fn):
        self.rsttcp = fn

    def _performHandover(self, sess):
        self.handover(sess)

    def _garbageCollector(self):
        self.lock.acquire()
        for sess in self.sessions[:]:  # type: TCPSesssion
            if sess.state in [TCPSesssion.STATE_CLOSED, TCPSesssion.STATE_TIMEOUT, TCPSesssion.STATE_CLOSED_RESET, TCPSesssion.STATE_HANDOVERED]:
                self.logger.info('Removing finished session ' + str(sess))
                self.sessions.remove(sess)
        self.lock.release()
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
        self.lock.acquire()
        for sess in self.sessions: #type: TCPSesssion
            if sess.ip.src == ip.src and \
                    sess.ip.dst == ip.dst and \
                    sess.ptcp.src_port == ptcp.src_port and \
                    sess.ptcp.dst_port == ptcp.dst_port:
                pkt = sess.handlePacket(pkt, eth, ip, ptcp)
                if (sess.handoverReady and not sess.handovered):
                    self.logger.debug('Handover is ready on SE too. Requesting CNT to do the dirty stuff')
                    self._performHandover(sess)
                    sess.handovered = True
                    self.lock.release()
                    return pkt, sess

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
            sess = TCPSesssion(pkt, eth, ip, ptcp, self)
            self.sessions.append(sess)
            self.lock.release()
            return pkt, None
        else:
            self.logger.error('Unexpected non SYN packet arrived to processing')

        self.logger.error("Packet went through pipeline without match")
        self.lock.release()
        return pkt, None
