from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.base import app_manager
from ryu.topology import switches
from ryu.topology import event as TopologyEvent
from ryu.controller import dpset
from ryu.controller.controller import Datapath
from ryu.controller.handler import set_ev_cls

from ryu.lib.packet import ether_types, packet, ethernet, ipv4, tcp
from ryu.ofproto import inet

from shared import ofprotoHelper
from modules.db.databaseEvents import EventDatabaseQuery, SetNodeInformationEvent
from modules.cdnmodule.models import Node, ServiceEngine, RequestRouter
from modules.cdnmodule.cdnEvents import EventCDNPipeline

from ryu import cfg
CONF = cfg.CONF


class CDNModule(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    opts = [
        cfg.IntOpt('table',
                default=1,
                help='Table to use for CDN Handling'),
        cfg.IntOpt('cookie',
                default=201,
                help='cookie to install'),
        cfg.IntOpt('node_priority',
                default=1,
                help='Priority to install CDN engine matching flows')
    ]

    _CONTEXTS = {
        'switches': switches.Switches,
        'dpset': dpset.DPSet
    }

    def __init__(self, *args, **kwargs):
        super(CDNModule, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='cdn')
        self.switches = kwargs['switches']
        self.dpset = kwargs['dpset']
        self.ofHelper = ofprotoHelper.ofProtoHelperGeneric()
        self.nodes = None
        self.update_lock = False

    def _install_cdnengine_matching_flow(self, datapath, ip, port):
        """
        Installs flow to match based on IP, port to datapath to send to controller
        :param datapath: dp_id
        :param ip: IP of http engine
        :param port: port of http engine
        :return:
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_dst=ip,
                                tcp_dst=port)
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.ofHelper.add_flow(datapath, CONF.cdn.node_priority, match, actions, CONF.cdn.table, CONF.cdn.cookie)

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=ip,
                                tcp_src=port)
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.ofHelper.add_flow(datapath, CONF.cdn.node_priority, match, actions, CONF.cdn.table, CONF.cdn.cookie)

    def _update_nodes(self):
        if not self.update_lock:
            self.update_lock = True
            req = EventDatabaseQuery('nodes')
            req.dst = 'DatabaseModule'
            self.nodes = self.send_request(req).data
            self.logger.debug('Updated Node List')
            self.update_lock = False

    @set_ev_cls(TopologyEvent.EventHostAdd, MAIN_DISPATCHER)
    def _host_in_event(self, ev):
        """
        This function if responsible for installing matching rules sending to controller if a SE or an RR joins the network
        List of RRs and SEs are defined in the database.json file
        :param ev:
        :type ev: TopologyEvent.EventHostAdd
        :return:
        """
        self._update_nodes()

        for node in self.nodes:
            if node.ip in ev.host.ipv4:
                datapath = self.dpset.get(ev.host.port.dpid)
                node.setPortInformation(ev.host.port.dpid, ev.host.port.port_no)
                self._install_cdnengine_matching_flow(datapath, node.ip, node.port)
                self.logger.info('New Node connected the network. Matching rules were installed ' + node.__str__())

    def _get_node_from_packet(self, ip, ptcp):
        """

        :param ip:
        :type ip: ipv4.ipv4
        :param ptcp:
        :type ptcp: tcp.tcp
        :return:
        """

        for node in self.nodes:
            if node.ip == ip.dst and node.port == ptcp.dst_port:
                return node
            if node.ip == ip.src and node.port == ptcp.src_port:
                return node
        return None

    @set_ev_cls(EventCDNPipeline, None)
    def cdnHandlingRequest(self, ev):
        """
        Handles the incoming TCP sessions towards RR or SE
        We only should receive packets destined to CDN engine (SE or RR) over TCP

        # TODO, cases that are not valid (not tcp, host not existing). Situations like this might happen on Controller restart

        :param ev:
        :type ev: EventCDNPipeline
        :return:
        """
        pkt = packet.Packet(ev.data)
        datapath = ev.datapath #type: Datapath

        eth = pkt.get_protocols(ethernet.ethernet)[0] #type: ethernet.ethernet
        ip = pkt.get_protocols(ipv4.ipv4)[0] #type: ipv4.ipv4
        ptcp = pkt.get_protocols(tcp.tcp)[0] #type: tcp.tcp

        node = self._get_node_from_packet(ip, ptcp)

        if node:
            node.handlePacket(pkt, eth, ip, ptcp)
        else:
            self.logger.error('Could not find node dest / source for the incoming packet packet {} {}', ip, ptcp)
