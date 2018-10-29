from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls

from modules.db.databaseEvents import EventDatabaseQuery, EventDatabaseResponse, SetNodeInformationEvent
from modules.db.model import DatabaseModel

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

    @set_ev_cls(EventDatabaseQuery, None)
    def getData(self, ev):
        """
        Build elif's for different keys
        :param ev:
        :return:
        """
        if ev.key == 'nodes':
            repl = EventDatabaseResponse(self.db.getNodes(), ev.src)
        else:
            repl = EventDatabaseResponse(None, ev.src)

        self.reply_to_request(ev, repl)

    @set_ev_cls(SetNodeInformationEvent, None)
    def setNodeData(self, ev):
        self.db.updateNode(ev.node)
        self.logger.info(self.db)