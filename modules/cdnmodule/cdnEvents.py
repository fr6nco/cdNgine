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
