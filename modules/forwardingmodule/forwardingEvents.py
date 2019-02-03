from ryu.controller import event


class EventForwardingPipeline(event.EventBase):
    """
    Use this if we want to send a random packet for forwarding pipeline
    """
    def __init__(self, datapath, match, data, doPktOut):
        super(EventForwardingPipeline, self).__init__()
        self.datapath = datapath
        self.match = match
        self.data = data
        self.doPktOut = doPktOut


class EventShortestPathRequest(event.EventRequestBase):
    """
    Use this request if we need a shortest path from source ip to dst ip
    """
    def __init__(self, src_ip, dst_ip):
        super(EventShortestPathRequest, self).__init__()
        self.src_ip = src_ip
        self.dst_ip = dst_ip


class EventShortestPathReply(event.EventReplyBase):
    """
    Use this as a reply to the ShortestPathRequest event. Returns a path
    """
    def __init__(self, path, dst):
        super(EventShortestPathReply, self).__init__(dst)
        self.path = path

class EventTopologyRequest(event.EventRequestBase):
    """
    Use this request if we need to query the topology
    """
    def __init__(self):
        super(EventTopologyRequest, self).__init__()


class EventTopologyReply(event.EventReplyBase):
    """
    Use this as a reply to EventTopologyRequest event. Returns a networkx topology
    """
    def __init__(self, topology, dst):
        super(EventTopologyReply, self).__init__(dst)
        self.topology = topology