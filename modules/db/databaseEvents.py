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