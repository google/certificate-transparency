import database
import gflags
import pymongo

from bson import binary
from ct.client.database import Database
from ct.proto.client_pb2 import SthResponse

FLAGS = gflags.FLAGS
gflags.DEFINE_string('mongodb_host', "127.0.0.1", "MongoDB host")
gflags.DEFINE_integer('mongodb_port', 27017, "MongoDB port")


class MongoDB(Database):
    def __init__(self, db):
        self.host = FLAGS.mongodb_host
        self.port = FLAGS.mongodb_port
        self.db = pymongo.MongoClient(self.host, self.port)[db]
        self.db.sth.ensure_index([("logid", pymongo.ASCENDING),
                                  ("timestamp", pymongo.DESCENDING)])

    def __repr__(self):
        return "%r(%r:%r, db:%r)" % (self.__class__.__name__,
                                     self.host, self.port, self.db)

    def __str__(self):
        ret = "%s(%s:%d, db:%s): " % (self.__class__.__name__,
                                      self.host, self.port, self.db)
        ret.append(' '.join(self.db.collection_names()))
        return ret
                   
    def _encode_sth(self, sth):
        return dict(logid=sth.log_server, timestamp=sth.timestamp,
                    data=binary.Binary(sth.SerializeToString()))

    def _decode_sth(self, sth_doc):
        sth = SthResponse()
        sth.ParseFromString(sth_doc["data"])
        return sth
        
    def store_sth(self, sth):
        to_store = self._encode_sth(sth)
        existing = self.db.sth.find_one({"logid":sth.log_server,
                                         "timestamp":sth.timestamp})
        if existing and existing["data"] == to_store["data"]:
            return
        self.db.sth.insert(self._encode_sth(sth))

    def get_latest_sth(self, logid):
        latest = self.db.sth.find({"logid":logid}).sort(
            "timestamp", pymongo.DESCENDING).limit(1)
        if latest.count():           
            return self._decode_sth(latest[0])
        
    def scan_latest_sth_range(self, logid, start=0, end=Database.timestamp_max,
                              limit=0):
        matcher = {"logid" : logid, "timestamp" : {"$gte": start, "$lte": end}}
        for match in self.db.sth.find(matcher).sort(
            "timestamp", pymongo.DESCENDING).limit(limit):
            yield self._decode_sth(match)
