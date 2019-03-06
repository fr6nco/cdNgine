from ryu.controller import event


class EventCDNPipeline(event.EventBase):
    """
    Use this if we want to send the packet for CDN pipeline
    """
    def __init__(self, datapath, match, data):
        super(EventCDNPipeline, self).__init__()
        self.datapath = datapath
        self.match = match
        self.data = data


class EventClosestSeRequest(event.EventRequestBase):
    """
    Use this request if we need to thet the closest SE to an IP
    """
    def __init__(self, ip):
        super(EventClosestSeRequest, self).__init__()
        self.ip = ip


class EventClosestSeReply(event.EventReplyBase):
    """
    Use this as a reply to EventClosestSeRequest. Returns IP of SE
    """
    def __init__(self, seip, dst):
        super(EventClosestSeReply, self).__init__(dst)
        self.seip = seip
