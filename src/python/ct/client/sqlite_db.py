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
                         "timestamp INTEGER, sth_data BLOB, "
                         "audit_info BLOB, UNIQUE("
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

    def update_log(self, metadata):
        log_server, serialized_metadata = self._encode_log_metadata(
            metadata)
        with self._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO logs(id, log_server, "
                         "metadata) VALUES((SELECT id FROM logs WHERE "
                         "log_server = ?), ?, ?) ", (log_server, log_server,
                                                     serialized_metadata))

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

    def _encode_sth(self, audited_sth):
        timestamp = audited_sth.sth.timestamp
        sth = client_pb2.SthResponse()
        sth.CopyFrom(audited_sth.sth)
        sth.ClearField("timestamp")
        audit = client_pb2.AuditInfo()
        audit.CopyFrom(audited_sth.audit)
        return (timestamp, buffer(sth.SerializeToString()),
                buffer(audit.SerializeToString()))

    def _decode_sth(self, sth_row):
        _, timestamp, serialized_sth, serialized_audit = sth_row
        audited_sth = client_pb2.AuditedSth()
        audited_sth.sth.ParseFromString(serialized_sth)
        audited_sth.sth.timestamp = timestamp
        audited_sth.audit.ParseFromString(serialized_audit)
        return audited_sth

    # This ignores a duplicate STH even if the audit data differs.
    # TODO(ekasper): add an update method for updating audit data, as needed.
    def store_sth(self, log_server, audited_sth):
        timestamp, sth_data, audit_info = self._encode_sth(audited_sth)
        with self._connect() as conn:
            log_id = self._get_log_id(conn, log_server)
            conn.execute("INSERT INTO sths(log_id, timestamp, sth_data, "
                         "audit_info) VALUES(?, ?, ?, ?)",
                         (log_id, timestamp, sth_data, audit_info))

    def get_latest_sth(self, log_server):
        row = None
        with self._connect() as conn:
            log_id = self._get_log_id(conn, log_server)
            res = conn.execute("SELECT * FROM sths WHERE log_id = ? "
                               "ORDER BY timestamp DESC LIMIT 1", (log_id,))
            try:
                row = res.next()
            except StopIteration:
                pass
        if row is not None:
            return self._decode_sth(row)

    def scan_latest_sth_range(self, log_server, start=0,
                              end=database.Database.timestamp_max, limit=0):
        sql_limit = -1 if not limit else limit
        with self._connect() as conn:
            log_id = self._get_log_id(conn, log_server)
            for row in conn.execute(
                "SELECT * FROM sths WHERE log_id = ? "
                "AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp DESC "
                "LIMIT ?", (log_id, start, end, sql_limit)):
                yield self._decode_sth(row)
