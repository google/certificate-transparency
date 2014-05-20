import abc
import hashlib
from ct.client import cert_db

# This class provides common tests for all cert database implementations.
# It only inherits from object so that unittest won't attempt to run the test_*
# methods on this class. Derived classes should use multiple inheritance
# from CertDBTest and unittest.TestCase to get test automation.
class CertDBTest(object):
    """All cert database tests should derive from this class as well as
    unittest.TestCase."""
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def db(self):
        """Derived classes must override to initialize a database."""
        pass

    def test_store_lookup_cert(self):
        self.db().store_cert("hello\x00", ["example.com"])
        sha256_hash = hashlib.sha256("hello\x00").digest()
        cert = self.db().get_cert_by_sha256_hash(sha256_hash)
        self.assertEqual("hello\x00", cert)

    def test_lookup_returns_none_if_no_match(self):
        self.db().store_cert("hello", ["example.com"])
        sha256_hash = hashlib.sha256("hello\x00").digest()
        self.assertIsNone(self.db().get_cert_by_sha256_hash(sha256_hash))

    def test_store_cert_ignores_duplicate(self):
        self.db().store_cert("hello\x00", ["example.com"])
        sha256_hash = hashlib.sha256("hello\x00").digest()
        cert = self.db().get_cert_by_sha256_hash(sha256_hash)
        self.assertEqual("hello\x00", cert)

        # Store again
        self.db().store_cert("hello\x00", ["example2.com"])
        certs = [c for c in self.db().scan_certs_by_subject("example.com")]
        self.assertEqual(1, len(certs))
        self.assertEqual("hello\x00", certs[0])
        certs = [c for c in self.db().scan_certs_by_subject("example2.com")]
        self.assertEqual(0, len(certs))

    def test_store_certs_stores_all(self):
        certs = [("hello-%d" % i, ["domain-%d.com" % i]) for i in range(4)]
        self.db().store_certs(certs)
        for i in range(4):
            sha256_hash = hashlib.sha256("hello-%d" % i).digest()
            cert = self.db().get_cert_by_sha256_hash(sha256_hash)
            self.assertEqual("hello-%d" % i, cert)

    def test_scan_certs_finds_all_certs(self):
        for i in range(4):
            self.db().store_cert("hello-%d" % i, ["domain-%d.com" % i])

        certs = {c for c in self.db().scan_certs()}
        self.assertEqual(4, len(certs))
        for i in range(4):
            self.assertTrue("hello-%d" % i in certs)

    def test_scan_certs_honours_limit(self):
        for i in range(4):
            self.db().store_cert("hello-%d" % i, ["domain-%d.com" % i])

        certs = {c for c in self.db().scan_certs(limit=2)}
        self.assertEqual(2, len(certs))

    def test_scan_certs_by_subject_finds_cert(self):
        for i in range(4):
            self.db().store_cert("hello-%d" % i, ["domain-%d.com" % i])

        for i in range(4):
            matches = [c for c in self.db().scan_certs_by_subject(
                    "domain-%d.com" % i)]
            self.assertEqual(1, len(matches))
            self.assertEqual("hello-%d" % i, matches[0])

    def test_scan_certs_by_subject_honours_limit(self):
        for i in range(4):
            self.db().store_cert("hello-%d" % i, ["domain.com"])

        matches = {c for c in self.db().scan_certs_by_subject("domain.com",
                                                              limit=2)}
        self.assertEqual(2, len(matches))

    def test_scan_certs_by_subject_finds_by_common_name(self):
        for i in range(4):
            self.db().store_cert("hello-%d" % i, ["Trusty CA %d" % i])

        for i in range(4):
            matches = [c for c in self.db().scan_certs_by_subject(
                    "Trusty CA %d" % i)]
            self.assertEqual(1, len(matches))
            self.assertEqual("hello-%d" % i, matches[0])

    def test_scan_certs_by_subject_finds_by_all_names(self):
        self.db().store_cert("hello", ["%d.com" % i for i in range(4)])

        for i in range(4):
            matches = [c for c in self.db().scan_certs_by_subject(
                    "%d.com" % i)]
            self.assertEqual(1, len(matches))
            self.assertEqual("hello", matches[0])

    def test_scan_certs_by_subject_finds_by_prefix(self):
        for i in range(4):
            self.db().store_cert("hello-%d" % i, [("%d." % i)*i +"example.com"])

        matches = {c for c in self.db().scan_certs_by_subject(
                "example.com")}
        self.assertEqual(4, len(matches))
        for i in range(4):
            self.assertTrue("hello-%d" % i in matches)

    def test_scan_certs_by_subject_ignores_longer(self):
        self.db().store_cert("hello", ["example.com"])

        matches = {c for c in self.db().scan_certs_by_subject(
                "mail.example.com")}
        self.assertEqual(0, len(matches))

    def test_scan_certs_by_subject_finds_by_literal_wildcard(self):
        self.db().store_cert("hello-wild", ["*.example.com"])
        self.db().store_cert("hello", ["www.example.com"])

        matches = [c for c in self.db().scan_certs_by_subject(
                "*.example.com")]
        self.assertEqual(1, len(matches))
        self.assertEqual("hello-wild", matches[0])

    def test_scan_certs_by_subject_ignores_wildcard_cert(self):
        for i in range(4):
            self.db().store_cert("hello-%d" % i, ["%d.example.com" % i])
        self.db().store_cert("hello-wild", ["*.example.com"])

        matches = {c for c in self.db().scan_certs_by_subject(
                "2.example.com")}
        self.assertEqual(1, len(matches))
        self.assertTrue("hello-2" in matches)
