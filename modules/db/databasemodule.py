from ryu.base import app_manager
from modules.db.model import DatabaseModel
from modules.forwardingmodule.forwardingEvents import EventTopologyReply, EventTopologyRequest

import json
from ryu import cfg
CONF = cfg.CONF


class DatabaseModule(app_manager.RyuApp):
    """
    Class for accessing the database json file
    """
    opts = [
        cfg.StrOpt('file',
                default='./config/database.json',
                help='Load database file'),
     ]

    def __init__(self, *args, **kwargs):
        super(DatabaseModule, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='database')
        self.dbFilePath = CONF.database.file

        try:
            with open(self.dbFilePath, 'r') as dbFile:
                self.dbobj = json.loads(dbFile.read())['cdngine']
        except IOError as e:
            self.logger.error('Failed to open file ' + e.message)
        except ValueError as e:
            self.logger.error('Failed to parse json ' + e.message)
        except Exception as e:
            self.logger.error('Unknown error occured while reading database file ' + e.message)
        finally:
            self.logger.info('Database file read')

        self.db = DatabaseModel(self.dbobj)

    def getData(self):
        return self.db

    def getTopology(self):
        toporeq = EventTopologyRequest()
        toporeq.dst = 'ForwardingModule'
        toporeq.sync = True
        reply = self.send_request(toporeq)  # type: EventTopologyReply
        return reply.topology
