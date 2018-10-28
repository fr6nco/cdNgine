from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

from shared import ofprotoHelper
from modules.forwardingmodule.forwardingEvents import EventForwardingPipeline

from ryu import cfg
CONF = cfg.CONF

"""
This module is going to handle the main pipeline
Table 0 -> used by RYU components
    Table 0 entries:
        RYU based stuff as LLDP and such
        GOTO 1
Table 1 -> Used by CDN Module
    Table 1 entries:
        SRC_IP:SRC_PORT_TCP:DST_IP:DST_PORT:TCP -> OUT_PORT, rewrite, IP, PORT, SEQ, ACK) (n vice versa x times)
        DST_IP:DST_PORT // SRC_IP:SRC_PORT matches SE -> Controller
        DST_IP:DST_PORT // SRC_IP:SRC_PORT matches RR -> Controller
        GOTO 2
Table 2 -> Used by Forwarding module
    Table 2 entries:
        SRC_MAC:DST_MAC:IN_PORT -> OUT_PORT (n vice versa x times) to enable basic forwarding
        Proto ARP: Controller
        NO_MATCH: Discard -> TODO: communication error on Controller reboot
"""
class cdNgine(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventForwardingPipeline]

    def __init__(self, *args, **kwargs):
        super(cdNgine, self).__init__(*args, **kwargs)
        self.ofHelper = ofprotoHelper.ofProtoHelperGeneric()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # GOTO rules
        match = parser.OFPMatch()
        self.ofHelper.add_goto(datapath, 0, match, 0, 1)
        self.ofHelper.add_goto(datapath, 0, match, 1, 2)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("Packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore lldp packets
            # LLDP packets are handled by ofp_helper
            return

        if msg.table_id == CONF.forwarding.table:
            fwev = EventForwardingPipeline(datapath, msg.match, msg.data)
            self.send_event('ForwardingModule', fwev)
