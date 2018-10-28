from ryu.controller import event

class EventDatabaseQuery(event.EventRequestBase):
    """
    Request for querying the database. Key will return the key of the object
    Current keys available:
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


class NodeInformationEvent(event.EventBase):
    def __init__(self, node):
        self.node = node
        super(NodeInformationEvent, self).__init__()


class SetNodeInformationEvent(NodeInformationEvent):
    """
    Sets information in the database about the node
    """
    def __init__(self, node):
        super(SetNodeInformationEvent, self).__init__(node)
