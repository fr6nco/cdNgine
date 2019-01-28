from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import packet
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
from ryu.lib import mac
from ryu.topology.switches import Port
from ryu.controller.controller import Datapath

import logging

LOG = logging.getLogger('ryu.base.app_manager')

UINT32_MAX = 0xffffffff


class ofProtoHelperGeneric():
    """
    Shared module for openflow manipulation
    """
    def add_goto(self, datapath, priority, match, from_table, to_table):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionGotoTable(to_table), ]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                                table_id=from_table)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, table_id, cookie=0, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, cookie=cookie,
                                    priority=priority, match=match, table_id=table_id,
                                    instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=table_id,
                                    cookie=cookie,
                                    match=match, instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)

        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, priority, match, table_id, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

        msg = parser.OFPFlowMod(datapath=datapath, table_id=table_id, priority=priority, match=match, instructions=inst,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout)

        datapath.send_msg(msg)

    def do_packet_out(self, data, datapath, port):
        """
        Does a packet out with no buffer
        :param data: Raw packed data
        :param datapath: Datapath Object
        :type datapath: Datapath
        :param port: Port object
        :type port: Port
        :return: nothing
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [parser.OFPActionOutput(port.port_no)]
        datapath.send_packet_out(buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)


    def del_flow_by_cookie(self, datapath, table_id, cookie):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, table_id=ofproto.OFPTT_ALL,
                                cookie=cookie, cookie_mask=0xffffffffffffffff, command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)

    ## Send ARP request
    def send_arp_request(self, datapath, src_mac, src_ip, dst_ip, output):
        ethertype_ether = ether_types.ETH_TYPE_ARP

        arp_opcode = arp.ARP_REQUEST
        hwtype = arp.ARP_HW_TYPE_ETHERNET
        ethertype_arp = ether_types.ETH_TYPE_IP
        hlen = 6
        plen = 4

        pkt = packet.Packet()
        e = ethernet.ethernet(src=src_mac, dst=mac.BROADCAST_STR, ethertype=ethertype_ether)
        a = arp.arp(hwtype=hwtype, proto=ethertype_arp, hlen=hlen, plen=plen, opcode=arp_opcode,
                    src_mac=src_mac, dst_mac=mac.DONTCARE_STR, src_ip=src_ip, dst_ip=dst_ip)
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        actions = [datapath.ofproto_parser.OFPActionOutput(output, 0)]

        res = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        LOG.info('Sending ARP Request for %s', dst_ip)
        datapath.send_msg(res)

    ## Send ARP response
    def send_arp_response(self, datapath, src_mac, dst_mac,
                          src_ip, dst_ip, output):
        # Generate ARP packet
        ethertype_ether = ether_types.ETH_TYPE_ARP

        arp_opcode = arp.ARP_REPLY
        hwtype = arp.ARP_HW_TYPE_ETHERNET
        ethertype_arp = ether_types.ETH_TYPE_IP
        hlen = 6
        plen = 4

        pkt = packet.Packet()
        e = ethernet.ethernet(src=src_mac, dst=dst_mac, ethertype=ethertype_ether)
        a = arp.arp(hwtype=hwtype, proto=ethertype_arp, hlen=hlen, plen=plen, opcode=arp_opcode,
                    src_mac=src_mac, dst_mac=dst_mac, src_ip=src_ip, dst_ip=dst_ip)
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(output, 0)]

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        res = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        LOG.info('Sending ARP response for %s', src_ip)
        datapath.send_msg(res)

    def send_packet_out(self, datapath, pkt, output):

        actions = [datapath.ofproto_parser.OFPActionOutput(output, 0)]

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        res = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        datapath.send_msg(res)

    def send_icmp_reply(self, datapath, old_pkt, output):

        pkt = packet.Packet()

        for protocol in old_pkt:
            if protocol.protocol_name == 'ethernet':
                e = ethernet.ethernet(src=protocol.dst, dst=protocol.src, ethertype=ether_types.ETH_TYPE_IP)
                pkt.add_protocol(e)
            elif protocol.protocol_name == 'ipv4':
                ip = ipv4.ipv4(version=protocol.version, header_length=protocol.header_length, tos=protocol.tos,
                               total_length=0, identification=protocol.identification,
                               flags=protocol.flags, offset=0, ttl=protocol.ttl, proto=protocol.proto, csum=0,
                               src=protocol.dst, dst=protocol.src, option=protocol.option)
                pkt.add_protocol(ip)
                dst_ip = ip.dst
            elif protocol.protocol_name == 'icmp':
                icm = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=protocol.data)
                pkt.add_protocol(icm)

        pkt.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(output, 0)]

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        res = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)

        LOG.info('Sending ICMP echo response for %s', dst_ip)
        datapath.send_msg(res)

    def send_icmp_port_unreachable(self, datapath, old_pkt, output):

        pkt = packet.Packet()
        datapkt = packet.Packet()

        dst_ip = None

        for protocol in old_pkt:
            if not hasattr(protocol, 'protocol_name'):
                datapkt.add_protocol(protocol)
            elif protocol.protocol_name == 'ethernet':
                e = ethernet.ethernet(src=protocol.dst, dst=protocol.src, ethertype=ether_types.ETH_TYPE_IP)
                pkt.add_protocol(e)
            elif protocol.protocol_name == 'ipv4':
                ip = ipv4.ipv4(dst=protocol.src, src=protocol.dst, proto=in_proto.IPPROTO_ICMP)
                dst_ip = protocol.src
                pkt.add_protocol(ip)
                datapkt.add_protocol(protocol)
            else:
                datapkt.add_protocol(protocol)

        datapkt.serialize()
        icm_data = icmp.dest_unreach(data=datapkt.data)
        icm = icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_PORT_UNREACH_CODE, csum=0, data=icm_data)

        pkt.add_protocol(icm)

        pkt.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(output, 0)]

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        res = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)

        LOG.info('Sending ICMP Port unreachable message for %s', dst_ip)
        datapath.send_msg(res)

