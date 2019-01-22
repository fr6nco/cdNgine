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
from modules.db.databasemodule import DatabaseModule

from modules.cdnmodule.models.node import Node
from modules.cdnmodule.models.ServiceEngine import ServiceEngine
from modules.cdnmodule.models.RequestRouter import RequestRouter
from modules.cdnmodule.models.TCPSession import TCPSesssion
from modules.cdnmodule.models.HandoverSesssion import HandoverSession

from modules.cdnmodule.cdnEvents import EventCDNPipeline

from modules.forwardingmodule.forwardingEvents import EventForwardingPipeline, EventShortestPathRequest, EventShortestPathReply
from modules.forwardingmodule.models import Path

from modules.wsendpointmodule.ws_endpoint import WsCDNEndpoint

import networkx as nx

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
                help='Priority to install CDN engine matching flows'),
        cfg.IntOpt('handover_priority',
                default=2,
                help='Priority to use for handover flows')
    ]

    _CONTEXTS = {
        'switches': switches.Switches,
        'dpset': dpset.DPSet,
        'db': DatabaseModule
    }

    def __init__(self, *args, **kwargs):
        super(CDNModule, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='cdn')
        self.switches = kwargs['switches']  # type: switches.Switches
        self.dpset = kwargs['dpset']  # type: dpset.DPSet
        self.db = kwargs['db']  # type: DatabaseModule
        self.ofHelper = ofprotoHelper.ofProtoHelperGeneric()
        self.nodes = []

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

    def _install_rewrite_dst_action_out(self, datapath, ip_src, port_src, ip_dst_old, port_dst_old, ip_dst_new, port_dst_new, new_dst_mac, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=ip_src, tcp_src=port_src, ipv4_dst=ip_dst_old, tcp_dst=port_dst_old)

        actions = [
            parser.OFPActionSetField(eth_dst=new_dst_mac),
            parser.OFPActionSetField(ipv4_dst=ip_dst_new),
            parser.OFPActionSetField(tcp_dst=port_dst_new),
            parser.OFPActionOutput(out_port)
        ]
        self.ofHelper.add_flow(datapath, CONF.cdn.handover_priority, match, actions, CONF.cdn.table)

    def _install_rewrite_src_action_out(self, datapath, ip_src_old, port_src_old, ip_src_new, port_src_new, ip_dst, port_dst, new_src_mac, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=ip_src_old, tcp_src=port_src_old, ipv4_dst=ip_dst, tcp_dst=port_dst)

        actions = [
            parser.OFPActionSetField(eth_src=new_src_mac),
            parser.OFPActionSetField(ipv4_src=ip_src_new),
            parser.OFPActionSetField(tcp_src=port_src_new),
            parser.OFPActionOutput(out_port)
        ]
        self.ofHelper.add_flow(datapath, CONF.cdn.handover_priority, match, actions, CONF.cdn.table)

    def _install_rewrite_dst_action_with_tcp_sa_out(self, datapath, ip_src, port_src, ip_dst_old, port_dst_old, ip_dst_new, port_dst_new, inc_seq, inc_ack, new_dst_mac, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=ip_src, tcp_src=port_src, ipv4_dst=ip_dst_old, tcp_dst=port_dst_old)

        actions = [
            parser.OFPActionSetField(eth_dst=new_dst_mac),
            parser.OFPActionSetField(ipv4_dst=ip_dst_new),
            parser.OFPActionSetField(tcp_dst=port_dst_new),
            parser.OFPActionIncSeq(inc_seq),
            parser.OFPActionIncAck(inc_ack),
            parser.OFPActionOutput(out_port)
        ]
        self.ofHelper.add_flow(datapath, CONF.cdn.handover_priority, match, actions, CONF.cdn.table)

    def _install_rewrite_src_action_with_tcp_sa_out(self, datapath, ip_src_old, port_src_old, ip_src_new, port_src_new, ip_dst, port_dst, inc_seq, inc_ack, new_src_mac, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=ip_src_old, tcp_src=port_src_old, ipv4_dst=ip_dst, tcp_dst=port_dst)

        actions = [
            parser.OFPActionSetField(eth_src=new_src_mac),
            parser.OFPActionSetField(ipv4_src=ip_src_new),
            parser.OFPActionSetField(tcp_src=port_src_new),
            parser.OFPActionIncSeq(inc_seq),
            parser.OFPActionIncAck(inc_ack),
            parser.OFPActionOutput(out_port)
        ]
        self.ofHelper.add_flow(datapath, CONF.cdn.handover_priority, match, actions, CONF.cdn.table)

    def _mitigate_tcp_session(self, datapath, src_ip, dst_ip, src_port, dst_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=src_ip, tcp_src=src_port, ipv4_dst=dst_ip, tcp_dst=dst_port)

        self.ofHelper.add_drop_flow(datapath, 2, match, CONF.cdn.table)


    def _update_nodes(self):
        self.nodes = self.db.getData().getNodes()

        for node in self.nodes:
            if node.type == 'rr':
                node.setHandoverCallback(self.get_closest_se_to_ip)
            if node.type == 'se':
                node.setHandoverCallback(self.perform_handover)
            node.setMitigateCallback(self.mitigatecb)

    def mitigatecb(self, datapath_id, src_ip, dst_ip, src_port, dst_port):
        for id, dp in self.switches.dps.iteritems():  # type: Datapath
            if id == datapath_id:
                self._mitigate_tcp_session(dp, src_ip, dst_ip, src_port, dst_port)

    def perform_handover(self, sess):
        """

        :param sess:
        :type sess: TCPSesssion
        :return:
        """
        hsess = sess.handoverPair  # type: HandoverSession
        self.logger.info('DOING HANDOVER IN CDN MODULE. DOING MAGIC')

        self.logger.info('Client established connection to RR:')
        self.logger.info('{}:{} -> {}.{}'.format(hsess.ip.src, hsess.ptcp.src_port, hsess.ip.dst, hsess.ptcp.dst_port))
        self.logger.info('Client sent HTTP Request')
        self.logger.info(hsess.httpRequest.raw_requestline)
        self.logger.info(hsess.httpRequest.headers)

        self.logger.info('CDN Engine decided to handover this session to service engine:')
        self.logger.info(str(hsess.serviceEngine))

        self.logger.info('RR pre established a Sesssion to the chosen SE:')
        self.logger.info('{}:{} -> {}.{}'.format(sess.ip.src, sess.ptcp.src_port, sess.ip.dst, sess.ptcp.dst_port))

        self.logger.info('After processing the Request Router sent a HTTP request to this SE which is')
        self.logger.info(sess.httpRequest.raw_requestline)
        self.logger.info(sess.httpRequest.headers)

        self.logger.info('Source SEQ on client-RR leg: %d', hsess.src_seq)
        self.logger.info('Dest SEQ on client-RR leg: %d', hsess.dst_seq)
        self.logger.info('Source SEQ on RR-SE leg: %d', sess.src_seq)
        self.logger.info('Dest SEQ on RR-SE leg: %d', sess.dst_seq)

        self.logger.info('Now do the maths and handover those')

        ## Handover procedure
        ## Request FW to isntall path from CL to SE <->
        ## UPDATE Flow mod on FW-acc switch
        ## Update Flow mod on SE-core switch

        spev = EventShortestPathRequest(hsess.ip.src, hsess.serviceEngine.ip)
        spev.dst = 'ForwardingModule'
        spev.sync = True

        pathres = self.send_request(spev)  # type: EventShortestPathReply
        if pathres.path:
            self.logger.info('FORWARD path')
            for p in pathres.path.fw:
                self.logger.info(p)

            self.logger.info('BACKWARD path')
            for p in pathres.path.bw:
                self.logger.info(p)

            # Rewrite DST IP and PORT from Client to RR -> SE on ACC switch in FW direction
            p = pathres.path.fw[1]  # 2nd entry on forwardp path
            for id, dp in self.switches.dps.iteritems():  # type: Datapath
                if id == p['src']:
                    self._install_rewrite_dst_action_out(dp, hsess.ip.src, hsess.ptcp.src_port, hsess.ip.dst, hsess.ptcp.dst_port, hsess.serviceEngine.ip, hsess.serviceEngine.port, sess.eth.dst, p['port'])

            p = pathres.path.bw[0]  # 1st entry on backward path
            for id, dp in self.switches.dps.iteritems():  # type: Datapath
                if id == p['src']:
                    self._install_rewrite_src_action_out(dp, hsess.serviceEngine.ip, hsess.serviceEngine.port, hsess.ip.dst, hsess.ptcp.dst_port, hsess.ip.src, hsess.ptcp.src_port, hsess.eth.dst, p['port'])

            ## Calculate seq ack diffs
            # Sinc_cs = ((2^32) + (Srs - Scr) + (Rrs - Rcr)) %% (2^32)
            self.logger.info('REQUEST SIZE RS %d CR %d', sess.request_size, hsess.request_size)
            seq_cs = ((2 ** 32) + (sess.src_seq - hsess.src_seq) + (sess.request_size - hsess.request_size)) % (2 ** 32)
            self.logger.info('SEQ CS %d', seq_cs)

            # Ainc_sc = ((2 ^ 32) - Sinc_cs) % % (2 ^ 32)
            ack_sc = ((2 ** 32) - seq_cs) % (2**32)
            self.logger.info('ACK SC %d', ack_sc)

            # Sinc_sc = ((2 ^ 32) + (Src - Ssr)) % % (2 ^ 32)
            seq_sc = ((2 ** 32) + (hsess.dst_seq - sess.dst_seq)) % (2 ** 32)
            self.logger.info('SEQ SC %d', seq_sc)

            # Ainc_cs = ((2 ^ 32) - Sinc_sc) % % (2 ^ 32)
            ack_cs = ((2 ** 32) - seq_sc) % (2 ** 32)
            self.logger.info('ACK CS %d', ack_cs)

            # Rewrite SRC IP and PORT from Client -> RR to SE and modify SEQ ACK on CR sw in FW direction
            p = pathres.path.fw[-1]
            for id, dp in self.switches.dps.iteritems():  # type: Datapath
                if id == p['src']:
                    self._install_rewrite_src_action_with_tcp_sa_out(dp, hsess.ip.src, hsess.ptcp.src_port, sess.ip.src, sess.ptcp.src_port, hsess.serviceEngine.ip, hsess.serviceEngine.port, seq_cs, ack_cs, sess.eth.src, p['port'])

            # Rewrite DST IP and PORT from SE to RR -> Client and modify SEQ ACK on CR sw in BW direction
            p = pathres.path.bw[-2]
            for id, dp in self.switches.dps.iteritems():  # type: Datapath
                if id == p['src']:
                    self._install_rewrite_dst_action_with_tcp_sa_out(dp, hsess.serviceEngine.ip, hsess.serviceEngine.port, sess.ip.src, sess.ptcp.src_port, hsess.ip.src, hsess.ptcp.src_port, seq_sc, ack_sc, hsess.eth.src, p['port'])

            rr = hsess.parentNode  # type: RequestRouter
            for id, dp in self.switches.dps.iteritems():
                if id == rr.datapath_id:
                    self._mitigate_tcp_session(dp, sess.ip.src, sess.ip.dst, sess.ptcp.src_port, sess.ptcp.dst_port)
                    self._mitigate_tcp_session(dp, sess.ip.dst, sess.ip.src, sess.ptcp.dst_port, sess.ptcp.src_port)
                    self.logger.info('Mitigating communication from RR towards network')

            self.logger.info('Path Installed from Client %s to Service Engine %s', hsess.ip.src, hsess.serviceEngine.ip)
        else:
            self.logger.error('Failed to retrieve path from Client to SE')


    def get_closest_se_to_ip(self, ip):
        switches = [dp for dp in self.switches.dps]
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in self.switches.links]

        g = nx.DiGraph()
        g.add_nodes_from(switches)
        g.add_edges_from(links)

        for mac, host in self.switches.hosts.iteritems():
            if ip in host.ipv4:
                g.add_node(ip)
                g.add_edge(ip, host.port.dpid)
                g.add_edge(host.port.dpid, ip, port=host.port.port_no)
            for node in self.nodes:
                if node.type == 'se' and node.ip in host.ipv4:
                    g.add_node(str(node.ip))
                    g.add_edge(str(node.ip), host.port.dpid)
                    g.add_edge(host.port.dpid, str(node.ip), port=host.port.port_no)

        lengths = nx.single_source_shortest_path_length(g, ip)
        lensrted = sorted(lengths.items(), key=lambda x: x[1])

        for distance in lensrted:
            for node in self.nodes:
                if node.type == 'se' and node.ip == distance[0]:
                    return node
        return None

    @set_ev_cls(TopologyEvent.EventHostAdd, MAIN_DISPATCHER)
    def _host_in_event(self, ev):
        """
        This function if responsible for installing matching rules sending to controller if a SE or an RR joins the
        network
        List of RRs and SEs are defined in the database.json file
        :param ev:
        :type ev: TopologyEvent.EventHostAdd
        :return:
        """
        self._update_nodes()

        if not self.nodes:
            return

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

    def _remove_tcp_options(self, pkt):
        eth = pkt.get_protocols(ethernet.ethernet)[0]  # type: ethernet.ethernet
        ip = pkt.get_protocols(ipv4.ipv4)[0]  # type: ipv4.ipv4
        ptcp = pkt.get_protocols(tcp.tcp)[0]  # type: tcp.tcp

        if(ptcp.has_flags(tcp.TCP_SYN)):
            new_ip = ipv4.ipv4(version=ip.version, header_length=5, tos=ip.tos, total_length=0,
                               identification=ip.identification, flags=ip.flags, offset=ip.offset,
                               ttl=ip.ttl, proto=ip.proto, csum=0, src=ip.src, dst=ip.dst, option=ip.option)

            # Remove TCP Timestamp and SACK permitted Option as it prevents the handover from working
            new_options = []
            for option in ptcp.option:  # type: tcp.TCPOption
                if not option.kind in [tcp.TCP_OPTION_KIND_TIMESTAMPS, tcp.TCP_OPTION_KIND_SACK_PERMITTED]:
                    new_options.append(option)

            new_ptcp = tcp.tcp(src_port=ptcp.src_port, dst_port=ptcp.dst_port, seq=ptcp.seq, ack=ptcp.ack,
                               offset=0, bits=ptcp.bits, window_size=ptcp.window_size, csum=0, urgent=ptcp.urgent,
                               option=new_options)

            new_pkt = packet.Packet()
            new_pkt.add_protocol(eth)
            new_pkt.add_protocol(new_ip)
            new_pkt.add_protocol(new_ptcp)
            new_pkt.serialize()

            return new_pkt
        else:
            return pkt

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
        datapath = ev.datapath  # type: Datapath

        # Removes all TCP options on SYN packets
        pkt = self._remove_tcp_options(pkt)

        eth = pkt.get_protocols(ethernet.ethernet)[0]  # type: ethernet.ethernet
        ip = pkt.get_protocols(ipv4.ipv4)[0]  # type: ipv4.ipv4
        ptcp = pkt.get_protocols(tcp.tcp)[0]  # type: tcp.tcp

        node = self._get_node_from_packet(ip, ptcp)  # type: Node

        if node:
            pkt = node.handlePacket(pkt, eth, ip, ptcp)  # type: packet.Packet
            fwev = EventForwardingPipeline(datapath=datapath, match=ev.match, data=pkt.data, doPktOut=True)
            self.send_event(name='ForwardingModule', ev=fwev)
        else:
            self.logger.error('Could not find node dest / source for the incoming packet packet {}'.format(ip))
