from ryu.controller import event

class EventForwardingRequest(event.EventBase):
    def __init__(self, datapath, match, data):
        super(EventForwardingRequest, self).__init__()
        self.datapath = datapath
        self.match = match
        self.data = data
