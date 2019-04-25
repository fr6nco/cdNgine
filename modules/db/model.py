from modules.cdnmodule.models.node import Node
from modules.cdnmodule.models.ServiceEngine import ServiceEngine
from modules.cdnmodule.models.RequestRouter import RequestRouter
from modules.cdnmodule.models.TCPSession import TCPSesssion
from modules.cdnmodule.models.HandoverSesssion import HandoverSession
import logging

class DatabaseModel(object):
    """
    Global store to store the data in a class object so its easier to access, read and write
    """
    def __init__(self, db):
        self.serialized_db = db
        self.nodes = []
        self.logger = logging.getLogger('DatabaseModule')
        self._loadData()

    def _loadData(self):
        for node in self.serialized_db['nodes']:
            n = Node.factory(**node)
            self.nodes.append(n)

    def getNodes(self):
        return self.nodes

    def getNodesByType(self, type):
        return filter(lambda x: x.type == type, self.getNodes())

    def updateNode(self, unode):
        for idx, node in enumerate(self.nodes):
            if node == unode:
                self.nodes[idx] = unode

    def getMatchingSess(self, src_ip, src_port, dst_ip, dst_port):
        for rr in self.getNodesByType('rr'):  # type: RequestRouter
            if rr.ip == dst_ip and rr.port == dst_port:
                for hsess in rr.handoverSessions:  # type: HandoverSession
                    if hsess.ip.src == src_ip and hsess.ptcp.src_port == src_port:
                        # This is required, because sometimes the data in threads are not synchronized
                        # and the SE won't be set even though it is set
                        # self.logger.info('Waiting for Event from Thread')
                        # res = hsess.event.wait()
                        sess = hsess.popDestinationSesssion()
                        return sess
        return None

    def setRequestSize(self, src_ip, src_port, dst_ip, dst_port, type, size):
        for node in self.getNodesByType(str(type)):
            if isinstance(node, RequestRouter):
                # If request router
                if node.ip == dst_ip and node.port == dst_port:
                    for hsess in node.handoverSessions:  # type: HandoverSession
                        if hsess.ip.src == src_ip and hsess.ptcp.src_port == src_port:
                            hsess.setRequestSize(size)
                            # We have to call the performhandover stuff, so the SE is set
                            # this is a redundant call, we just want to make sure se is chosen.
                            node._performHandover(hsess)
                            return True
            else:
                # If service engine
                if node.ip == dst_ip and node.port == dst_port:
                    for sess in node.sessions:  # type: TCPSesssion
                        if sess.ip.src == src_ip and sess.ptcp.src_port == src_port:
                            sess.setRequestSize(size)
                            return True

        self.logger.error('Could not find session to set request size')
        return False

    def getAllSessions(self):
        sessions = []
        for rr in self.getNodesByType('rr'):  # type: RequestRouter
            for hsess in rr.handoverSessions:  # type: HandoverSession
                session = {
                    'type': 'rr',
                    'src_ip': hsess.ip.src,
                    'dst_ip': hsess.ip.dst,
                    'src_port': hsess.ptcp.src_port,
                    'dst_port': hsess.ptcp.dst_port,
                    'state': hsess.state,
                    'handovered': True if hsess.handovered else False,
                    'handover_ready': True if hsess.handoverReady else False
                }
                sessions.append(session)
        for se in self.getNodesByType('se'):  # type: ServiceEngine
            for sess in se.sessions:  # type: TCPSesssion
                session = {
                    'type': 'se',
                    'src_ip': sess.ip.src,
                    'dst_ip': sess.ip.dst,
                    'src_port': sess.ptcp.src_port,
                    'dst_port': sess.ptcp.dst_port,
                    'state': sess.state,
                    'handovered': True if sess.handovered else False,
                    'handover_ready': True if sess.handoverReady else False
                }
                sessions.append(session)
        return sessions

    def __str__(self):
        return "Current database model:\n" \
               "############\n" \
               "Nodes:\n" + \
               "\n".join([str(node) for node in self.nodes]) + \
               '\n############'
