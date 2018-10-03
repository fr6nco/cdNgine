from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls, set_ev_handler
from ryu.ofproto import ofproto_v1_3

from ryu.topology import switches
from ryu.controller import dpset

from ryu.lib.packet import ether_types, packet, ethernet, arp

import modules

from ryu import cfg
CONF = cfg.CONF

from shared import ofprotoHelper

import networkx

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
                help='FLow mod cookie to use for Controller event on arp')
    ]

    def __init__(self, *args, **kwargs):
        super(ForwardingModule, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='forwarding')
        self.switches = kwargs['switches']
        self.dpset = kwargs['dpset']
        self.ofHelper = ofprotoHelper.ofProtoHelperGeneric()

    def start(self):
        super(ForwardingModule, self).start()

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

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.ofHelper.add_flow(datapath, 0, match, actions, CONF.forwarding.table, CONF.forwarding.cookie_arp)

    def do_packet_out(self, data, datapath, port):
        """
        Does a packet out with no buffer
        :param data: Raw packed data
        :param datapath: Datapath Object
        :param port: Port object
        :return: nothing
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [parser.OFPActionOutput(port.port_no)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(modules.forwardingmodule.forwardingEvents.EventForwardingRequest, None)
    def forwardingRequest(self, ev):
        datapath = ev.datapath
        match = ev.match

        pkt = packet.Packet(ev.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arpp = pkt.get_protocols(arp.arp)[0]
            if arpp.opcode in [arp.ARP_REQUEST, arp.ARP_REPLY]:
                self.logger.info('we are looking for %s:%s from %s:%s', arpp.dst_ip, arpp.dst_mac, arpp.src_ip, arpp.src_mac)
                host = [x for key, x in self.switches.hosts.iteritems() if x.ipv4[0] == arpp.dst_ip]
                if host:
                    host = host[0]
                    self.do_packet_out(ev.data, self.switches.dps[host.port.dpid], host.port)
                else:
                    nonAccessPorts = []
                    for link, ts in self.switches.links.iteritems():
                        nonAccessPorts.extend((link.src, link.dst))
                    accessPorts = [port for port, portdata in self.switches.ports.iteritems() if port not in nonAccessPorts]

                    # Send packet out to all access ports instead of flood
                    for port in accessPorts:
                        self.do_packet_out(ev.data, self.switches.dps[port.dpid], port)

        else:
            pass
            """
            We are going to make shortest path calculation here and feed the switches with the appropriate flow mods and vice versas
            No solving topology changes so far
            
            feed host A and B to nx graph, feed all switches to NX graph, add links between hosts and swithces and do shortest path
            """




