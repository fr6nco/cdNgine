from modules.cdnmodule.models import RequestRouter, ServiceEngine, Node


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

    def updateNode(self, unode):
        for idx, node in enumerate(self.nodes):
            if node == unode:
                self.nodes[idx] = unode

    def __str__(self):
        return "Current database model:\n" \
               "############\n" \
               "Nodes:\n" + \
               "\n".join([str(node) for node in self.nodes]) + \
               '\n############'
