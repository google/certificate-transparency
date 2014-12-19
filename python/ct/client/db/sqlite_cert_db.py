import sqlite3
import gflags

from ct.client.db import cert_db
from ct.client.db import cert_desc

FLAGS = gflags.FLAGS

gflags.DEFINE_bool("cert_db_sqlite_synchronous_write", True, "If set to true, "
                   "sqlite will use synchronous write.")

class SQLiteCertDB(cert_db.CertDB):
    def __init__(self, connection_manager):
        """Initialize the database and tables.
        Args:
            connection: an SQLiteConnectionManager object."""
        self.__mgr = connection_manager
        self.cert_repeated_field_tables = [("subject_names", [("name", "TEXT")]),
                                    ("alt_subject_names", [("name", "TEXT")]),
                                    ("ip_addresses", [("ip_address", "TEXT")])]
        cert_single_field_tables = [("version", "INTEGER"),
                                    ("serial_number", "TEXT")]
        self.cert_table_columns = [column for column, _ in cert_single_field_tables]
        with self.__mgr.get_connection() as conn:
            # the |cert| BLOB is also unique but we don't force this as it would
            # create a superfluous index.
            conn.execute("CREATE TABLE IF NOT EXISTS certs("
                         "log INTEGER,"
                         "id INTEGER,"
                         "sha256_hash BLOB UNIQUE,"
                         "cert BLOB," +
                         ', '.join(['%s %s' % (column, type_) for column, type_
                                    in cert_single_field_tables]) +
                         ", PRIMARY KEY(log, id))")
            for entry in self.cert_repeated_field_tables:
                self.__create_table_for_field(conn, *entry)
            conn.execute("CREATE INDEX IF NOT EXISTS certs_by_subject "
                         "on subject_names(name)")
        self.__tables = (["logs", "certs"] +
                         [column for column, _ in self.cert_repeated_field_tables])

    @staticmethod
    def __create_table_for_field(conn, table_name, fields):
        """Helper method that creates table for given certificate field. Each
        row in that table refers to some certificate in certs table.
        Args:
            table_name:   name of the table
            fields:       iterable of (column_name, type) tuples"""
        conn.execute("CREATE TABLE IF NOT EXISTS {table_name}("
                     "log INTEGER, cert_id INTEGER,"
                     "{fields},"
                     "FOREIGN KEY(log, cert_id) REFERENCES certs(log, id))"
                     .format(table_name=table_name,
                             fields=','.join(
                                     ["%s %s" % field for field in fields])))

    def __repr__(self):
        return "%r(db: %r)" % (self.__class__.__name__, self.__db)

    def __str__(self):
        return "%s(db: %s, tables: %s): " % (self.__class__.__name__, self.__db,
                                             self.__tables)


    @staticmethod
    def __compare_processed_names(prefix, name):
        return prefix == name[:len(prefix)]

    def __store_cert(self, cert, index, log_key, cursor):
        der_cert = cert.der
        if not FLAGS.cert_db_sqlite_synchronous_write:
            cursor.execute("PRAGMA synchronous = OFF")
        try:
            cursor.execute("INSERT INTO certs(log, id, sha256_hash, cert, %s) "
                           "VALUES(?, ?, ?, ?, %s) " %
                                    (','.join(self.cert_table_columns),
                                    ('?,' * len(self.cert_table_columns))[:-1]),
                           [log_key, index,
                            sqlite3.Binary(self.sha256_hash(der_cert)),
                            sqlite3.Binary(der_cert)] +
                            [cert[column] for column in self.cert_table_columns])
        except sqlite3.IntegrityError:
            # cert already exists
            return
        for table_name, columns in self.cert_repeated_field_tables:
            column_names = [column for column, _ in columns]
            if cert[table_name]:
                for field in cert[table_name]:
                    cursor.execute("INSERT INTO %s(log, cert_id, %s) VALUES(?, ?, %s)" %
                                       (table_name, ','.join(column_names),
                                        ('?,' * len(column_names))[:-1]),
                                   [log_key, index] + field)

    def store_certs_desc(self, certs, log_key):
        """Store certificates using it's descriptions.

        Args:
            certs:         iterable of (CertificateDescription, index) tuples
            log_key:       log id in LogDB"""
        with self.__mgr.get_connection() as conn:
            cursor = conn.cursor()
            for cert in certs:
                self.__store_cert(cert[0], cert[1], log_key, cursor)

    def store_cert_desc(self, cert, index, log_key):
        """Store certificate using it's description.

        Args:
            cert:          CertificateDescription
            index:         position in log
            log_key:       log id in LogDB"""
        self.store_certs_desc([(cert, index)], log_key)

    def get_cert_by_sha256_hash(self, cert_sha256_hash):
        """Fetch a certificate with a matching SHA256 hash
        Args:
            cert_sha256_hash: the SHA256 hash of the certificate
        Returns:
            A DER-encoded certificate, or None if the cert is not found."""
        with self.__mgr.get_connection() as conn:
            res = conn.execute("SELECT cert FROM certs WHERE sha256_hash == ?",
                               (sqlite3.Binary(cert_sha256_hash),))
            try:
                return str(res.next()["cert"])
            except StopIteration:
                pass

    def scan_certs(self, limit=0):
        """Scan all certificates.
        Args:
            limit: maximum number of entries to yield. Default is no limit.
        Yields:
            DER-encoded certificates."""
        sql_limit = -1 if not limit else limit
        with self.__mgr.get_connection() as conn:
            for row in conn.execute(
                "SELECT cert FROM certs LIMIT ?", (sql_limit,)):
                yield str(row["cert"])

    # RFC 2818 (HTTP over TLS) states that "names may contain the wildcard
    # character * which is considered to match any single domain name
    # component or component fragment."
    #
    # So theoretically a cert for www.*.com or www.e*.com is valid for
    # www.example.com (although common browsers reject overly broad certs).
    # This makes wildcard matching in index scans difficult.
    #
    # The subject index scan thus does not match wildcards: it is not intended
    # for fetching all certificates that may be deemed valid for a given domain.
    # Applications should define their own rules for detecting wildcard certs
    # and anything else of interest.
    def scan_certs_by_subject(self, subject_name, limit=0):
        """Scan certificates matching a subject name.
        Args:
            subject_name: a subject name, usually a domain. A scan for
                          example.com returns certificates for www.example.com,
                          *.example.com, test.mail.example.com, etc. Similarly
                          'com' can be used to look for all .com certificates.
                          Wildcards are treated as literal characters: a search
                          for *.example.com returns certificates for
                          *.example.com but not for mail.example.com and vice
                          versa.
                          Name may also be a common name rather than a DNS name,
                          e.g., "Trustworthy Certificate Authority".
            limit:        maximum number of entries to yield. Default is no
                          limit.
        Yields:
            DER-encoded certificates."""
        sql_limit = -1 if not limit else limit
        prefix = cert_desc.process_name(subject_name)
        with self.__mgr.get_connection() as conn:
            for row in conn.execute(
                "SELECT certs.cert as cert, subject_names.name as name "
                "FROM certs, subject_names WHERE name >= ? AND certs.id == "
                "subject_names.cert_id ORDER BY name ASC LIMIT ?",
                (".".join(prefix), sql_limit)):
                name = cert_desc.process_name(row["name"], reverse=False)
                if self.__compare_processed_names(prefix, name):
                    yield str(row["cert"])
                else:
                    break
