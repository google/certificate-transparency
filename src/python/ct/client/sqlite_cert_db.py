import sqlite3
import hashlib
import logging
import re
import contextlib

from ct.client import cert_db
from ct.client import sqlite_connection as sqlitecon

class SQLiteCertDB(cert_db.CertDB):
    def __init__(self, connection_manager):
        """Initialize the database and tables.
        Args:
            connection: an SQLiteConnectionManager object."""
        self.__mgr = connection_manager

        with self.__mgr.get_connection() as conn:
            # the |cert| BLOB is also unique but we don't force this as it would
            # create a superfluous index.
            conn.execute("CREATE TABLE IF NOT EXISTS certs("
                         "id INTEGER PRIMARY KEY, "
                         "sha256_hash BLOB UNIQUE, cert BLOB)")
            conn.execute("CREATE TABLE IF NOT EXISTS subject_names("
                         "cert_id INTEGER, name TEXT, FOREIGN KEY(cert_id)"
                         "REFERENCES certs(id))")
            conn.execute("CREATE INDEX IF NOT EXISTS certs_by_subject "
                         "on subject_names(name)")
        self.__tables = ["certs", "subject_names"]

    def __repr__(self):
        return "%r(db: %r)" % (self.__class__.__name__, self.__db)

    def __str__(self):
        return "%s(db: %s, tables: %s): " % (self.__class__.__name__, self.__db,
                                             self.__tables)

    @staticmethod
    # TODO(ekasper): this belongs in x509_name.
    def __process_name(subject, reverse=True):
        # RFCs for DNS names: RFC 1034 (sect. 3.5), RFC 1123 (sect. 2.1);
        # for common names: RFC 5280.
        # However we probably do not care about full RFC compliance here
        # (e.g. we ignore that a compliant label cannot begin with a hyphen,
        # we accept multi-wildcard names, etc.).
        #
        # For now, make indexing work for the common case:
        # allow letter-digit-hyphen, as well as wildcards (RFC 2818).
        forbidden = re.compile(r"[^a-z\d\-\*]")
        subject = subject.lower()
        labels = subject.split(".")
        valid = all(map(lambda x: len(x) and not forbidden.search(x), labels))

        if valid:
            # ["com", "example", "*"], ["com", "example", "mail"],
            # ["localhost"], etc.
            return list(reversed(labels)) if reverse else labels

        else:
            # ["john smith"], ["trustworthy certificate authority"],
            # ["google.com\x00"], etc.
            # TODO(ekasper): figure out what to do (use stringprep as specified
            # by RFC 5280?) to properly handle non-letter-digit-hyphen names.
            return [subject]

    @staticmethod
    def __compare_processed_names(prefix, name):
        return prefix == name[:len(prefix)]

    def __store_cert(self, der_cert, subject_names, cursor):
        try:
            cursor.execute("INSERT INTO certs(sha256_hash, cert) VALUES(?, ?) ",
                           (sqlite3.Binary(self.sha256_hash(der_cert)),
                            sqlite3.Binary(der_cert)))
        except sqlite3.IntegrityError:
            # cert already exists
            return
        cid = cursor.lastrowid
        for subject in subject_names:
            # ["com", "example"] => "com.example"
            prefix = ".".join(self.__process_name(subject))
            cursor.execute("INSERT INTO subject_names(cert_id, name) "
                           "VALUES(?, ?)", (cid, prefix))

    def store_cert(self, der_cert, subject_names):
        """Store a certificate, unless it already exists.
        Args:
            der_cert:      the DER-encoded certificate
            subject_names: an iterable of subject names, used to create a search
                           index."""
        self.store_certs([(der_cert, subject_names)])

    def store_certs(self, certs):
        """Batch store certificates as a single transaction. Use this for bulk
        operations, as transactions are expensive.
        Args:
            certs: an iterable of (der_cert, subject_names) tuples.
        """
        with self.__mgr.get_connection() as conn:
            cursor = conn.cursor()
            for cert in certs:
                self.__store_cert(cert[0], cert[1], cursor)

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
        prefix = self.__process_name(subject_name)
        with self.__mgr.get_connection() as conn:
            for row in conn.execute(
                "SELECT certs.cert as cert, subject_names.name as name "
                "FROM certs, subject_names WHERE name >= ? AND certs.id == "
                "subject_names.cert_id ORDER BY name ASC LIMIT ?",
                (".".join(prefix), sql_limit)):
                name = self.__process_name(row["name"], reverse=False)
                if self.__compare_processed_names(prefix, name):
                    yield str(row["cert"])
                else:
                    break
