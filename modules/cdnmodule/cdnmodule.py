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

        self.shortestPathtoSefromIPCache = []

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
        self.ofHelper.add_flow(datapath, CONF.cdn.handover_priority, match, actions, CONF.cdn.table, 0, None, 1, 0)

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
        self.ofHelper.add_flow(datapath, CONF.cdn.handover_priority, match, actions, CONF.cdn.table, 0, None, 1, 0)

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
        self.ofHelper.add_flow(datapath, CONF.cdn.handover_priority, match, actions, CONF.cdn.table, 0, None, 1, 0)

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
        self.ofHelper.add_flow(datapath, CONF.cdn.handover_priority, match, actions, CONF.cdn.table, 0, None, 1, 0)

    def _mitigate_tcp_session(self, datapath, src_ip, dst_ip, src_port, dst_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=src_ip, tcp_src=src_port, ipv4_dst=dst_ip, tcp_dst=dst_port)

        self.ofHelper.add_drop_flow(datapath, 2, match, CONF.cdn.table, 1, 0)

    def _generate_rsts(self, hsess):
        """

        :param hsess:
        :type hsess: HandoverSession
        :return:
        """
        hsess_eth = hsess.eth
        hsess_ip = ipv4.ipv4(version=hsess.ip.version, header_length=5, tos=hsess.ip.tos, total_length=0,
                           identification=hsess.ip.identification, flags=hsess.ip.flags, offset=hsess.ip.offset,
                           ttl=hsess.ip.ttl, proto=hsess.ip.proto, csum=0, src=hsess.ip.src, dst=hsess.ip.dst, option=hsess.ip.option)
 
        hsess_ptcp = tcp.tcp(src_port=hsess.ptcp.src_port, dst_port=hsess.ptcp.dst_port,
                             seq=hsess.src_seq + hsess.request_size + 1, ack=hsess.dst_seq + 1,
                             offset=0, bits=(tcp.TCP_ACK | tcp.TCP_RST), window_size=hsess.ptcp.window_size, csum=0,
                             urgent=hsess.ptcp.urgent,
                             option=None)

        hsess_rst = packet.Packet()
        hsess_rst.add_protocol(hsess_eth)
        hsess_rst.add_protocol(hsess_ip)
        hsess_rst.add_protocol(hsess_ptcp)
        hsess_rst.serialize()
        
        sess = hsess.handoverPair
        sess_eth = ethernet.ethernet(dst=sess.eth.src, src=sess.eth.dst, ethertype=sess.eth.ethertype)

        sess_ip = ipv4.ipv4(version=sess.ip.version, header_length=5, tos=sess.ip.tos, total_length=0,
                           identification=sess.ip.identification, flags=sess.ip.flags, offset=sess.ip.offset,
                           ttl=sess.ip.ttl, proto=sess.ip.proto, csum=0, src=sess.ip.dst, dst=sess.ip.src, option=sess.ip.option)

        sess_ptcp = tcp.tcp(src_port=sess.ptcp.dst_port, dst_port=sess.ptcp.src_port,
                             seq=sess.dst_seq + 1, ack=sess.src_seq + sess.request_size + 1,
                             offset=0, bits=(tcp.TCP_ACK | tcp.TCP_RST), window_size=sess.ptcp.window_size, csum=0,
                             urgent=sess.ptcp.urgent,
                             option=None)

        sess_rst = packet.Packet()
        sess_rst.add_protocol(sess_eth)
        sess_rst.add_protocol(sess_ip)
        sess_rst.add_protocol(sess_ptcp)
        sess_rst.serialize()

        return hsess_rst, sess_rst


    def _update_nodes(self):
        self.nodes = self.db.getData().getNodes()

        for node in self.nodes:
            if node.type == 'rr':
                node.setHandoverCallback(self.get_closest_se_to_ip)
            if node.type == 'se':
                node.setHandoverCallback(self.perform_handover)
                node.setRSTCallback(self.rsttcpSessioncb)
            node.setMitigateCallback(self.mitigatecb)

    def mitigatecb(self, datapath_id, src_ip, dst_ip, src_port, dst_port):
        for id, dp in self.switches.dps.iteritems():  # type: Datapath
            if id == datapath_id:
                self._mitigate_tcp_session(dp, src_ip, dst_ip, src_port, dst_port)

    def rsttcpSessioncb(self, sess):
        hsess = sess.handoverPair
        #
        # Send Reset packets towards request router
        hsess_rst, sess_rst = self._generate_rsts(hsess)
        self.ofHelper.do_packet_out(hsess_rst, hsess.parentNode.datapath_obj, hsess.parentNode.port_obj)
        self.ofHelper.do_packet_out(sess_rst, hsess.parentNode.datapath_obj, hsess.parentNode.port_obj)


    def perform_handover(self, sess):
        """

        :param sess:
        :type sess: TCPSesssion
        :return:
        """
        hsess = sess.handoverPair  # type: HandoverSession
        self.logger.debug('DOING HANDOVER IN CDN MODULE. DOING MAGIC')

        self.logger.debug('Client established connection to RR:')
        self.logger.debug('{}:{} -> {}.{}'.format(hsess.ip.src, hsess.ptcp.src_port, hsess.ip.dst, hsess.ptcp.dst_port))
        self.logger.debug('Client sent HTTP Request')
        self.logger.debug(hsess.httpRequest.raw_requestline)
        self.logger.debug(hsess.httpRequest.headers)

        self.logger.debug('CDN Engine decided to handover this session to service engine:')
        self.logger.debug(str(hsess.serviceEngine))

        self.logger.debug('RR pre established a Sesssion to the chosen SE:')
        self.logger.debug('{}:{} -> {}.{}'.format(sess.ip.src, sess.ptcp.src_port, sess.ip.dst, sess.ptcp.dst_port))

        self.logger.debug('After processing the Request Router sent a HTTP request to this SE which is')
        self.logger.debug(sess.httpRequest.raw_requestline)
        self.logger.debug(sess.httpRequest.headers)

        self.logger.debug('Source SEQ on client-RR leg: %d', hsess.src_seq)
        self.logger.debug('Dest SEQ on client-RR leg: %d', hsess.dst_seq)
        self.logger.debug('Source SEQ on RR-SE leg: %d', sess.src_seq)
        self.logger.debug('Dest SEQ on RR-SE leg: %d', sess.dst_seq)

        self.logger.debug('Now do the maths and handover those')


        spev = EventShortestPathRequest(hsess.ip.src, hsess.serviceEngine.ip)
        spev.dst = 'ForwardingModule'
        spev.sync = True

        pathres = self.send_request(spev)  # type: EventShortestPathReply
        if pathres.path:
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
            self.logger.debug('REQUEST SIZE RS %d CR %d', sess.request_size, hsess.request_size)
            seq_cs = ((2 ** 32) + (sess.src_seq - hsess.src_seq) + (sess.request_size - hsess.request_size)) % (2 ** 32)
            self.logger.debug('SEQ CS %d', seq_cs)

            # Ainc_sc = ((2 ^ 32) - Sinc_cs) % % (2 ^ 32)
            ack_sc = ((2 ** 32) - seq_cs) % (2**32)
            self.logger.debug('ACK SC %d', ack_sc)

            # Sinc_sc = ((2 ^ 32) + (Src - Ssr)) % % (2 ^ 32)
            seq_sc = ((2 ** 32) + (hsess.dst_seq - sess.dst_seq)) % (2 ** 32)
            self.logger.debug('SEQ SC %d', seq_sc)

            # Ainc_cs = ((2 ^ 32) - Sinc_sc) % % (2 ^ 32)
            ack_cs = ((2 ** 32) - seq_sc) % (2 ** 32)
            self.logger.debug('ACK CS %d', ack_cs)

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

            # Mitigate all corresponding communication from to request router
            self._mitigate_tcp_session(hsess.parentNode.datapath_obj, sess.ip.src, sess.ip.dst, sess.ptcp.src_port, sess.ptcp.dst_port)
            self._mitigate_tcp_session(hsess.parentNode.datapath_obj, sess.ip.dst, sess.ip.src, sess.ptcp.dst_port, sess.ptcp.src_port)
            self.logger.info('Mitigating communication from RR towards network')

            hsess.state = HandoverSession.STATE_HANDOVERED
            sess.state = TCPSesssion.STATE_HANDOVERED

            self.logger.info('Handovered and path Installed from Client %s to Service Engine %s', hsess.ip.src, hsess.serviceEngine.ip)
        else:
            self.logger.error('Failed to retrieve path from Client to SE')

    def get_closest_se_to_ip(self, ip):
        cache = dict(self.shortestPathtoSefromIPCache)
        if ip in cache:
            return cache[ip]

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
                    self.shortestPathtoSefromIPCache.append((ip, node))
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
                node.setPortInformation(ev.host.port.dpid, datapath, ev.host.port.port_no, ev.host.port)
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
            pkt, sess = node.handlePacket(pkt, eth, ip, ptcp)  # type: packet.Packet, TCPSesssion
            fwev = EventForwardingPipeline(datapath=datapath, match=ev.match, data=pkt.data, doPktOut=True)
            self.send_event(name='ForwardingModule', ev=fwev)
            if sess is not None:
                self.rsttcpSessioncb(sess)
                self.logger.info('We are sending 2 RSTs to the RR ass sess was returned')
        else:
            self.logger.error('Could not find node dest / source for the incoming packet packet {}'.format(ip))
