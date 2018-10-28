from ryu.controller import event

class EventDatabaseQuery(event.EventRequestBase):
    """
    Request for querying the database. Key will return the key of the object
    Current keys available:
    -rrs
    -ses
    """
    def __init__(self, key):
        super(EventDatabaseQuery, self).__init__()
        self.key = key


class EventDatabaseResponse(event.EventReplyBase):
    """
    Returns an array of values
    """
    def __init__(self, data, dst):
        super(EventDatabaseResponse, self).__init__(dst)
        self.data = data

class UpdateNodeInformationEvent(event.EventBase):
    """
    Sets information in the database about the node
    """
    def __init__(self, node_type, node_name, datapath_id, port_id):
        super(UpdateNodeInformationEvent, self).__init__()
        self.node_type = node_type
        self.node_name = node_name
        self.datapath_id = datapath_id
        self.port_id = port_id