from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls

from modules.db.databaseEvents import EventDatabaseQuery, EventDatabaseResponse, SetNodeInformationEvent

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
                self.db = json.loads(dbFile.read())['cdngine']
        except IOError as e:
            self.logger.error('Failed to open file ' + e.message)
        except ValueError as e:
            self.logger.error('Failed to parse json ' + e.message)
        except Exception as e:
            self.logger.error('Unknown error occured while reading database file ' + e.message)
        finally:
            self.logger.info('Database file read')

    @set_ev_cls(EventDatabaseQuery, None)
    def getData(self, ev):
        repl = EventDatabaseResponse(self.db[ev.key], ev.src)
        self.reply_to_request(ev, repl)

    @set_ev_cls(SetNodeInformationEvent, None)
    def setNodeData(self, ev):
        for idx, node in enumerate(self.db['nodes']):
            if node['name'] == ev.node.name:
                self.db['nodes'][idx] = ev.node.serialize()
        self.logger.debug('Updated node information ' + json.dumps(self.db))
