from ryu.lib.packet import packet, tcp, ethernet, ipv4

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
        self.sessions = []
        super(ServiceEngine, self).__init__(**kwargs)

    def __str__(self):
        return 'Service Engine node. HTTP engine on {}:{:d}'.format(self.ip, self.port) + \
            '. Attached to Access Switch {} port id {:d}'.format(self.datapath_id, self.port_id) if self.datapath_id else ''

    def __eq__(self, other):
        return isinstance(other, ServiceEngine) and \
               self.name == other.name and \
               self.ip == other.ip and \
               self.port == other.port

    def handlePacket(self, pkt, eth, ip, tcp):
        pass


class RequestRouter(Node):
    def __init__(self, **kwargs):
        self.type = 'rr'
        self.handoverSessions = []
        super(RequestRouter, self).__init__(**kwargs)

    def __str__(self):
        return 'Request Router node. HTTP engine on {}:{:d}'.format(self.ip, self.port) + \
            '. Attached to Access Switch {} port id {:d}'.format(self.datapath_id, self.port_id) if self.datapath_id else ''

    def __eq__(self, other):
        return isinstance(other, RequestRouter) and \
               self.name == other.name and \
               self.ip == other.ip and \
               self.port == other.port

    def handlePacket(self, pkt, eth, ip, ptcp):
        """
        Handles packet and returns the packet. Packet might change

        :param pkt:
        :param eth:
        :type eth: ethernet.ethernet
        :param ip:
        :type ip: ipv4.ipv4
        :param ptcp:
        :type ptcp: tcp.tcp
        :return:
        """
        found = False
        for sess in self.handoverSessions: #type: HandoverSession
            if sess.ip.src == ip.src and \
                    sess.ip.dst == ip.dst and \
                    sess.ptcp.src_port == ptcp.src_port and \
                    sess.ptcp.dst_port == ptcp.dst_port:
                found = True
                return sess.handlePacket(pkt, eth, ip, ptcp)
            if sess.ip.dst == ip.src and \
                    sess.ip.src == ip.dst and \
                    sess.ptcp.src_port == ptcp.dst_port and \
                    sess.ptcp.dst_port == ptcp.src_port:
                found = True
                return sess.handlePacket(pkt, eth, ip, ptcp)

        if not found:
            # Create a new TCP session if the existin session is not found
            sess = TCPSesssion(pkt, eth, ip, ptcp)
            self.handoverSessions.append(sess)
            return pkt



class TCPSesssion():
    def __init__(self, pkt, eth, ip, ptcp):
        """

        :param pkt:
        :param eth:
        :type eth: ethernet.ethernet
        :param ip:
        :type ip: ipv4.ipv4
        :param ptcp:
        :type ptcp: tcp.tcp
        :return:
        """
        # MAIN STATES
        STATE_OPENING = 'opening'
        STATE_ESTABLISHED = 'established'
        STATE_CLOSING = 'closing'
        STATE_TIME_WAIT = 'close_time_wait'

        STATE_TIMEOUT_TIME_WAIT = 'timeout_wait'
        STATE_TIMEOUT = "timeout"

        STATE_CLOSED_RESET_TIME_WAIT = "reset_wait"
        STATE_CLOSED_RESET = "reset"
        STATE_CLOSED = "closed"

        # SUBStates for endpoints
        CLIENT_STATE_SYN_SENT = "c_syn_sent"
        SERVER_STATE_SYN_RCVD = "s_syn_rcvd"

        CLOSING_FIN_SENT = "fin_sent"

        self.pkt_syn = pkt

        self.eth = eth
        self.ip = ip
        self.ptcp = ptcp
        self.state = STATE_OPENING
        self.client_state = CLIENT_STATE_SYN_SENT
        self.server_state = None
        self.src_seq = ptcp.seq


    def handlePacket(self, pkt, eth, ip, ptcp):
        return pkt



class HandoverSession(TCPSesssion):
    def __init__(self, pkt, eth, ip, ptcp):
        super(HandoverSession, self).__init__(pkt, eth, ip, ptcp)
