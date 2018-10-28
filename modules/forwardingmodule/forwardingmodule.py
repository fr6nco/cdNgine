from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls, set_ev_handler
from ryu.ofproto import ofproto_v1_3

from ryu.topology import switches
from ryu.controller import dpset

from ryu.lib.packet import ether_types, packet, ethernet, arp, ipv4

import modules

from ryu import cfg
CONF = cfg.CONF

from shared import ofprotoHelper

import networkx as nx

class ForwardingModule(app_manager.RyuApp):
    """
    Generic forwarding module. Wont listen to Packet in messages but other modules
    will trigger when they need forwarding

    Table 2 -> Used by Forwarding module
        Table 2 entries:
            SRC_MAC:DST_MAC:IN_PORT -> OUT_PORT (n vice versa x times) to enable basic forwarding
            Proto ARP: Controller
            NO_MATCH: Discard -> TODO: communication error on Controller reboot
    """
    _CONTEXTS = {
        'switches': switches.Switches,
        'dpset': dpset.DPSet
    }

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    opts = [
        cfg.IntOpt('table',
                default=2,
                help='Table to use for forwarding'),
        cfg.IntOpt('cookie_arp',
                default=101,
                help='FLow mod cookie to use for Controller event on arp'),
        cfg.IntOpt('priority',
                default=1,
                help='Priority to use to add the forwarding rules')
    ]

    def __init__(self, *args, **kwargs):
        super(ForwardingModule, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='forwarding')
        self.switches = kwargs['switches']
        self.dpset = kwargs['dpset']
        self.ofHelper = ofprotoHelper.ofProtoHelperGeneric()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Loads ARP action to send arp packets to controller
        :param ev:
        :return:
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.ofHelper.add_flow(datapath, 0, match, actions, CONF.forwarding.table, CONF.forwarding.cookie_arp)

    def add_forwarding_rule(self, datapath, src_ip, dst_ip, out_port):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = [
            parser.OFPActionOutput(out_port)
        ]
        self.ofHelper.add_flow(datapath, CONF.forwarding.priority, match, actions, CONF.forwarding.table)

    def apply_forwarding_path(self, path, src_ip, dst_ip):
        for rule in path['fw']:
            if isinstance(rule['src'], int):
                self.add_forwarding_rule(self.switches.dps[rule['src']], src_ip, dst_ip, rule['port'])
        for rule in path['bw']:
            if isinstance(rule['src'], int):
                self.add_forwarding_rule(self.switches.dps[rule['src']], dst_ip, src_ip, rule['port'])

    def get_shortest_path(self, src_ip, dest_ip):
        switches = [dp for dp in self.switches.dps]
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in self.switches.links]

        g = nx.DiGraph()
        g.add_nodes_from(switches)
        g.add_edges_from(links)

        for mac, host in self.switches.hosts.iteritems():
            if dest_ip in host.ipv4:
                g.add_node(dest_ip)
                g.add_edge(dest_ip, host.port.dpid)
                g.add_edge(host.port.dpid, dest_ip, port=host.port.port_no)
            if src_ip in host.ipv4:
                g.add_node(src_ip)
                g.add_edge(src_ip, host.port.dpid)
                g.add_edge(host.port.dpid, src_ip, port=host.port.port_no)

        try:
            path = nx.shortest_path(g, src_ip, dest_ip)
        except nx.NodeNotFound:
            return None

        edge_data = {'fw': [], 'bw': []}

        for i in range(0, len(path) - 1):
            edged = g.get_edge_data(path[i], path[i+1])
            edge_data['fw'].append({
                'src': path[i],
                'dst': path[i+1],
                'port': edged['port'] if 'port' in edged else ''
            })
            edged = g.get_edge_data(path[i+1], path[i])
            edge_data['bw'].append({
                'src': path[i+1],
                'dst': path[i],
                'port': edged['port'] if 'port' in edged else ''
            })

        return edge_data

    @set_ev_cls(modules.forwardingmodule.forwardingEvents.EventShortestPathRequest, None)
    def requestShortestPath(self, ev):
        path = self.get_shortest_path(ev.src_ip, ev.dst_ip)
        reply = modules.forwardingmodule.forwardingEvents.EventShortestPathReply(path=path)
        self.reply_to_request(ev, reply)

    @set_ev_cls(modules.forwardingmodule.forwardingEvents.EventForwardingPipeline, None)
    def forwardingRequest(self, ev):
        datapath = ev.datapath
        match = ev.match

        pkt = packet.Packet(ev.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            """
            This part is responsible for handling ARP's, Arps are only recived and sent on access port to eliminiate forwarding loops
            """
            arpp = pkt.get_protocols(arp.arp)[0]
            if arpp.opcode in [arp.ARP_REQUEST, arp.ARP_REPLY]:
                self.logger.info('we are looking for %s:%s from %s:%s', arpp.dst_ip, arpp.dst_mac, arpp.src_ip, arpp.src_mac)
                host = [x for key, x in self.switches.hosts.iteritems() if x.ipv4[0] == arpp.dst_ip]
                if host:
                    host = host[0]
                    self.ofHelper.do_packet_out(ev.data, self.switches.dps[host.port.dpid], host.port)
                else:
                    nonAccessPorts = []
                    for link, ts in self.switches.links.iteritems():
                        nonAccessPorts.extend((link.src, link.dst))
                    accessPorts = [port for port, portdata in self.switches.ports.iteritems() if port not in nonAccessPorts]

                    # Send packet out to all access ports instead of flood
                    for port in accessPorts:
                        self.ofHelper.do_packet_out(ev.data, self.switches.dps[port.dpid], port)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocols(ipv4.ipv4)[0]

            path = self.get_shortest_path(ip.src, ip.dst)
            if path:
                self.apply_forwarding_path(path, ip.src, ip.dst)

