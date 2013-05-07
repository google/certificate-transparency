import contextlib
import logging
import sqlite3

from ct.client import database
from ct.proto import client_pb2

class SQLiteDB(database.Database):
    def __init__(self, db, keepalive=False):
        """Initialize the database and tables.
        Args:
            db: database file, or ":memory:"
            keepalive: If True, causes the connection to be kept open.
                       If False, causes a new connection to be created for each
                       operation.
                       keepalive=True is not thread-safe.
        """
        self.db = db
        self.keepalive=keepalive
        self.conn = None
        if keepalive:
           self.conn = self._get_conn()

        with self._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS logs("
                         "id INTEGER PRIMARY KEY, log_server TEXT UNIQUE, "
                         "metadata BLOB)")
            conn.execute("CREATE TABLE IF NOT EXISTS sths(log_id INTEGER, "
                         "timestamp INTEGER, sth_data BLOB, UNIQUE("
                         "log_id, timestamp, sth_data) ON CONFLICT IGNORE, "
                         "FOREIGN KEY(log_id) REFERENCES logs(id))")
            conn.execute("CREATE INDEX IF NOT EXISTS sth_by_timestamp on sths("
                         "log_id, timestamp)")
        self.tables = ["logs", "sths"]

    def __repr__(self):
        return "%r(db:%r)" % (self.__class__.__name__, self.db)

    def __str__(self):
        ret = "%s(db:%s): " % (self.__class__.__name__, self.db)
        ret.append(' '.join(self.tables))
        return ret

    def _get_conn(self):
        # The default timeout is 5 seconds.
        # TODO(ekasper): tweak this as needed
        return sqlite3.connect(self.db)

    # 'with' causes automatic commit (or rollback and raise) for an
    # sqlite connection. However it does not close the connection, so we need
    # our own context manager for this.
    @contextlib.contextmanager
    def _connect(self):
        """In keepalive mode, yields the single persistent connection.
        Else yields a new connection instance that will be automatically
        closed upon __exit__."""
        c = None
        if self.conn is not None:
            close_on_exit = False
            c = self.conn
        else:
            close_on_exit = True
            c = self._get_conn()
        try:
            with c:
                yield c
        # Note: The sqlite3 module does not document its error conditions so
        # it'll probably take a few iterations to get the exceptions right.
        except sqlite3.OperationalError as e:
            raise database.OperationalError(e)
        finally:
            if close_on_exit:
                c.close()

    def _encode_log_metadata(self, metadata):
        log_server = metadata.log_server
        local_metadata = client_pb2.CtLogMetadata()
        local_metadata.CopyFrom(metadata)
        local_metadata.ClearField("log_server")
        return log_server, buffer(local_metadata.SerializeToString())

    def _decode_log_metadata(self, log_server, serialized_metadata):
        metadata = client_pb2.CtLogMetadata()
        metadata.ParseFromString(serialized_metadata)
        metadata.log_server = log_server
        return metadata

    def add_log(self, metadata):
        log_server, serialized_metadata = self._encode_log_metadata(
            metadata)
        with self._connect() as conn:
            try:
                conn.execute("INSERT INTO logs(log_server, metadata) "
                             "VALUES(?, ?)", (log_server, serialized_metadata))
            except sqlite3.IntegrityError:
                logging.warning("Ignoring duplicate log server %s", log_server)

    def logs(self):
        with self._connect() as conn:
            for log_server, metadata in conn.execute(
                "SELECT log_server, metadata FROM logs"):
                yield self._decode_log_metadata(log_server, metadata)

    def _get_log_id(self, conn, log_server):
        res = conn.execute("SELECT id FROM logs WHERE log_server = ?",
                           (log_server,))
        try:
            log_id = res.next()
        except StopIteration:
            raise database.KeyError("Unknown log server: %s", log_server)
        return log_id[0]

    def _encode_sth(self, sth):
        timestamp = sth.timestamp
        local_sth = client_pb2.SthResponse()
        local_sth.CopyFrom(sth)
        local_sth.ClearField("timestamp")
        return timestamp, buffer(local_sth.SerializeToString())

    def _decode_sth(self, timestamp, serialized_sth):
        sth = client_pb2.SthResponse()
        sth.ParseFromString(serialized_sth)
        sth.timestamp = timestamp
        return sth

    def store_sth(self, log_server, sth):
        timestamp, sth_data = self._encode_sth(sth)
        with self._connect() as conn:
            log_id = self._get_log_id(conn, log_server)
            conn.execute("INSERT INTO sths(log_id, timestamp, sth_data) "
                         "VALUES(?, ?, ?)", (log_id, timestamp, sth_data))

    def get_latest_sth(self, log_server):
        timestamp, sth_data = None, None
        with self._connect() as conn:
            log_id = self._get_log_id(conn, log_server)
            res = conn.execute("SELECT timestamp, sth_data FROM sths "
                               "WHERE log_id = ? ORDER BY timestamp DESC "
                               "LIMIT 1", (log_id,))
            try:
                timestamp, sth_data = res.next()
            except StopIteration:
                pass
        if timestamp is not None:
            return self._decode_sth(timestamp, sth_data)

    def scan_latest_sth_range(self, log_server, start=0,
                              end=database.Database.timestamp_max, limit=0):
        sql_limit = -1 if not limit else limit
        with self._connect() as conn:
            log_id = self._get_log_id(conn, log_server)
            for timestamp, sth_data in conn.execute(
                "SELECT timestamp, sth_data FROM sths WHERE log_id = ? "
                "AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC "
                "LIMIT ?", (log_id, start, end, sql_limit)):
                  yield self._decode_sth(timestamp, sth_data)
