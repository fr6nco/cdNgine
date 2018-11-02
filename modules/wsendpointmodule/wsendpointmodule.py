from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3

from ryu.app.wsgi import WSGIApplication

from modules.db.databasemodule import DatabaseModule
from modules.wsendpointmodule.ws_endpoint import WsCDNEndpoint

from ryu import cfg
CONF = cfg.CONF


class WsEndpointModule(app_manager.RyuApp):
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
        'wsgi': WSGIApplication,
        'db': DatabaseModule
    }

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    opts = []

    def __init__(self, *args, **kwargs):
        super(WsEndpointModule, self).__init__(*args, **kwargs)

        self.db = kwargs['db']  # type: DatabaseModule
        self.wsgi = kwargs['wsgi']  # type: WSGIApplication

        self._initwsEndpoint()

    def _initwsEndpoint(self):
        self.incoming_rpc_connections = []

        self.wsgi.register(WsCDNEndpoint, data={
            'db': self.db
        })

