import logging

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
        self.mitigate = None
        super(Node, self).__init__()

    def factory(**kwargs):
        from modules.cdnmodule.models.RequestRouter import RequestRouter
        from modules.cdnmodule.models.ServiceEngine import ServiceEngine

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
        """
        Calls back to the cdnModule
        :param fn:
        :return:
        """
        return

    def setMitigateCallback(self, fn):
        """
        Calls back to the cdnModule
        :param fn:
        :return:
        """
        self.mitigate = fn

    def setPortInformation(self, datapath_id, datapath, port_id, port):
        self.datapath_id = datapath_id
        self.datapath_obj = datapath
        self.port_id = port_id
        self.port_obj = port
