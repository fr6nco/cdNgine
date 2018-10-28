from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.base import app_manager
from ryu.topology import switches
from ryu.topology import event as TopologyEvent
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls

from ryu.lib.packet import ether_types
from ryu.ofproto import inet

from ryu import cfg
CONF = cfg.CONF

from shared import ofprotoHelper
from modules.db import databaseEvents
from models import Node, ServiceEngine, RequestRouter

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

    def _save_node_state(self, node):
        set_node_state_ev = databaseEvents.SetNodeInformationEvent(node)
        self.send_event('DatabaseModule', set_node_state_ev)

    def _install_cdnengine_matching_flow(self, datapath, ip, port):
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


    @set_ev_cls(TopologyEvent.EventHostAdd, MAIN_DISPATCHER)
    def _host_in_event(self, ev):
        """
        This function if responsible for installing matching rules sending to controller if a SE or an RR joins the network
        List of RRs and SEs are defined in the database.json file
        :param ev:
        :return:
        """
        if not self.nodes:
            req = databaseEvents.EventDatabaseQuery('nodes')
            req.dst = 'DatabaseModule'
            self.nodes = self.send_request(req).data
            self.logger.info('Updated Node List')

        for node in self.nodes:
            if node['ip'] in ev.host.ipv4:
                n = Node.factory(**node)
                datapath = self.dpset.get(ev.host.port.dpid)
                n.setPortInformation(ev.host.port.dpid, ev.host.port.port_no)
                self._install_cdnengine_matching_flow(datapath, n.ip, n.port)
                self._save_node_state(n)
                self.logger.info('New Node connected the network. Matching rules were installed ' + n.__str__())


