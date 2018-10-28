

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
        super(ServiceEngine, self).__init__(**kwargs)

    def __str__(self):
        return 'Service Engine node. HTTP engine on {}:{:d}'.format(self.ip, self.port) + \
            '. Attached to Access Switch {} port id {:d}'.format(self.datapath_id, self.port_id) if self.datapath_id else ''

class RequestRouter(Node):
    def __init__(self, **kwargs):
        self.type = 'rr'
        super(RequestRouter, self).__init__(**kwargs)

    def __str__(self):
        return 'Request Router node. HTTP engine on {}:{:d}'.format(self.ip, self.port) + \
            '. Attached to Access Switch {} port id {:d}'.format(self.datapath_id, self.port_id) if self.datapath_id else ''
