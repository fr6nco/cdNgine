from ryu.app.wsgi import (
    ControllerBase,
    websocket,
    WebSocketRPCServer,
    rpc_public
)

from modules.db.databasemodule import DatabaseModule
from modules.cdnmodule.models import RequestRouter, ServiceEngine

import networkx as nx
from networkx import json_graph
import logging
import json

url = '/cdnhandler/ws'

class WsCDNEndpoint(ControllerBase):
    def __init__(self, req, link, data, **config):
        self.logger = logging.getLogger('wsgi, ws')
        self.logger.info("WSGI endpoint initiated")
        self.incoming_rpc_connections = []

        self.db = data['db']  # type: DatabaseModule

        super(WsCDNEndpoint, self).__init__(req, link, data, **config)

    def tracer(self, dir, context, msg):
        self.logger.debug("{}: {}".format(dir, msg))

    @rpc_public
    def hello(self, ip, port):
        self.logger.info('Request Router with http params {}:{} saying hello'.format(ip, port))
        rrs = self.db.getData().getNodesByType('rr')

        for rr in rrs:  # type: RequestRouter
            if rr.ip == ip and rr.port == port:
                return {'code': 200, 'res': {'name': rr.serialize()['name'], 'domain': rr.serialize()['domain']}}
        return {'code': 404, 'res': 'rr not found'}

    @rpc_public
    def getrrs(self):
        self.logger.info('Requesting All Request Routers')
        rrs = self.db.getData().getNodesByType('rr')
        return {'code': 200, 'res': [{'name': x['name'], 'ip': x['ip'], 'port': x['port'], 'domain': x['domain']}
                                     for x in map(lambda y: y.serialize(), rrs)]}

    @rpc_public
    def getses(self):
        self.logger.info('Request router requesting Service Engines')
        ses = self.db.getData().getNodesByType('se')
        return {'code': 200, 'res': [{'name': x['name'], 'ip': x['ip'], 'port': x['port'], 'domain': x['domain']}
                                     for x in map(lambda y: y.serialize(), ses)]}

    @rpc_public
    def getclosestse(self, ip):
        self.logger.info('Requesting closest service engine for ip {}'.format(ip))
        ip = self.db.getData().getClosestSeToIP(ip)
        if ip:
            return {'code': 200, 'res': ip}
        else:
            return {'code': 400, 'res': 'Service Engine not found'}

    @rpc_public
    def getmatchingsess(self, src_ip, src_port, dst_ip, dst_port):
        self.logger.info('Request Router requesting matching session for {}:{}<->{}:{}'.format(src_ip, src_port, dst_ip, dst_port))
        matchingsess = self.db.getData().getMatchingSess(src_ip, src_port, dst_ip, dst_port)
        if matchingsess:
            return {'code': 200, 'res': {'src_ip': matchingsess.ip.src, 'src_port': matchingsess.ptcp.src_port,
                                         'dst_ip': matchingsess.ip.dst, 'dst_port': matchingsess.ptcp.dst_port}}
        else:
            return {'code': 404, 'res': 'Failed to Retrieve Destination Session'}

    @rpc_public
    def setrequestsize(self, src_ip, src_port, dst_ip, dst_port, type, requestsize):
        self.logger.info('Request router sending the size of the raw request for {}:{}<->{}:{}'.format(src_ip, src_port, dst_ip, dst_port))
        saved = self.db.getData().setRequestSize(src_ip, src_port, dst_ip, dst_port, type, requestsize)
        if saved:
            return {'code': 200, 'res': 'Request Size saved'}
        else:
            return {'code': 404, 'res': 'Session not found'}

    @rpc_public
    def getallsessions(self):
        self.logger.info('Requesting all available sessions')
        return {'code': 200, 'res': self.db.getData().getAllSessions()}

    @rpc_public
    def gettopology(self):
        self.logger.info('Requesting Topology via WS RPC')
        topo = self.db.getTopology()  # type: nx.DiGraph
        return {'code': 200, 'res': json_graph.node_link_data(topo)}

    @websocket('wscdn', url)
    def _websocket_handler(self, ws):
        rpc_server = WebSocketRPCServer(ws, self)
        rpc_server.trace = self.tracer
        rpc_server.serve_forever()
