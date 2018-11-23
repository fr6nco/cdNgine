from modules.cdnmodule.models import RequestRouter, ServiceEngine, Node, HandoverSession, TCPSesssion


class DatabaseModel(object):
    """
    Global store to store the data in a class object so its easier to access, read and write
    """
    def __init__(self, db):
        self.serialized_db = db
        self.nodes = []
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
                if rr.writesem.acquire(blocking=True, timeout=1):
                    print 'received lock'
                    for hsess in rr.handoverSessions:  # type: HandoverSession
                        if hsess.ip.src == src_ip and hsess.ptcp.src_port == src_port:
                            sess = hsess.popDestinationSesssion()
                            rr.writesem.release()
                            print 'released lock'
                            return sess
                    rr.writesem.release()
        return None

    def __str__(self):
        return "Current database model:\n" \
               "############\n" \
               "Nodes:\n" + \
               "\n".join([str(node) for node in self.nodes]) + \
               '\n############'
