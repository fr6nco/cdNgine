from ryu.app.wsgi import (
    ControllerBase,
    websocket,
    WebSocketRPCServer,
    rpc_public
)

from modules.db.databasemodule import DatabaseModule

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

    @rpc_public
    def hello(self):
        self.logger.info('Request Router with http params hello registering')

    def tracer(self, dir, context, msg):
        self.logger.info("{}: {}".format(dir, msg))

    @websocket('wscdn', url)
    def _websocket_handler(self, ws):
        rpc_server = WebSocketRPCServer(ws, self)
        rpc_server.trace = self.tracer
        rpc_server.serve_forever()
