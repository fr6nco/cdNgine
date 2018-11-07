from ryu.app.wsgi import (
    ControllerBase,
    websocket,
    WebSocketRPCServer,
    rpc_public
)

from modules.db.databasemodule import DatabaseModule
from modules.cdnmodule.models import RequestRouter, ServiceEngine

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
        self.logger.info("{}: {}".format(dir, msg))

    @rpc_public
    def hello(self, ip, port):
        self.logger.info('Request Router with http params {}:{} saying hello'.format(ip, port))
        rrs = self.db.getData().getNodesByType('rr')

        for rr in rrs:  # type: RequestRouter
            if rr.ip == ip and rr.port == port:
                return {'code': 200, 'res': rr.serialize()['name']}
        return {'code': 404, 'res': 'rr not found'}

    @rpc_public
    def getses(self):
        self.logger.info('Request router requesting Service Engines')
        ses = self.db.getData().getNodesByType('se')
        return {'code': 200, 'res': [{'name': x['name'], 'ip': x['ip'], 'port': x['port']} for x in map(lambda x: x.serialize(), ses)]}


    @websocket('wscdn', url)
    def _websocket_handler(self, ws):
        rpc_server = WebSocketRPCServer(ws, self)
        rpc_server.trace = self.tracer
        rpc_server.serve_forever()
