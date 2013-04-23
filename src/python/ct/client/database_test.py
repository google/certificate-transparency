import abc
from ct.proto.client_pb2 import SthResponse

# This class provides common tests for all database implementations.
# It only inherits from object so that unittest won't attempt to run the test_*
# methods on this class. Derived classes should use multiple inheritance
# from DatabaseTest and unittest.TestCase to get test automation.
class DatabaseTest(object):
    """All Database tests should derive from this class as well as
    unittest.TestCase."""
    __metaclass__ = abc.ABCMeta

    # Set up a default fake test STH.
    default_sth = SthResponse()
    default_sth.log_server = "test"
    default_sth.timestamp = 1234
    default_sth.sha256_root_hash = "hash"

    @abc.abstractmethod
    def db(self):
        """Derived classes MUST override to initialize a database."""
        raise NotImplementedError()
        
    def test_store_sth(self):
        self.db().store_sth(DatabaseTest.default_sth)
        read_sth = self.db().get_latest_sth(DatabaseTest.default_sth.log_server)
        self.assertTrue(read_sth)
        self.assertEqual(DatabaseTest.default_sth.timestamp, read_sth.timestamp)
        self.assertEqual(DatabaseTest.default_sth.sha256_root_hash,
                         read_sth.sha256_root_hash)

    def test_get_latest_sth_returns_latest(self):
        self.db().store_sth(DatabaseTest.default_sth)
        new_sth = SthResponse()
        new_sth.CopyFrom(DatabaseTest.default_sth)
        new_sth.timestamp = DatabaseTest.default_sth.timestamp - 1
        self.db().store_sth(new_sth)
        read_sth = self.db().get_latest_sth(DatabaseTest.default_sth.log_server)
        self.assertIsNotNone(read_sth)
        self.assertEqual(DatabaseTest.default_sth.timestamp, read_sth.timestamp)
        self.assertEqual(DatabaseTest.default_sth.sha256_root_hash,
                         read_sth.sha256_root_hash)
        
    def test_get_latest_sth_honours_log_server(self):
        self.db().store_sth(DatabaseTest.default_sth)
        new_sth = SthResponse()
        new_sth.CopyFrom(DatabaseTest.default_sth)
        new_sth.timestamp = DatabaseTest.default_sth.timestamp + 1
        new_sth.log_server = "test2"
        new_sth.sha256_root_hash = "hash2"
        self.db().store_sth(new_sth)
        read_sth = self.db().get_latest_sth(DatabaseTest.default_sth.log_server)
        self.assertIsNotNone(read_sth)
        self.assertEqual(DatabaseTest.default_sth.timestamp, read_sth.timestamp)
        self.assertEqual(DatabaseTest.default_sth.sha256_root_hash,
                         read_sth.sha256_root_hash)

    def test_scan_latest_sth_range_finds_all(self):
        for i in range(4):
            sth = SthResponse()
            sth.log_server = "test"
            sth.timestamp = i
            sth.sha256_root_hash = "hash-%d" % i
            self.db().store_sth(sth)

        generator = self.db().scan_latest_sth_range("test")
        for i in range(4):
            sth = generator.next()
            self.assertEqual(sth.log_server, "test")
            # Scan runs in descending timestamp order
            self.assertEqual(sth.timestamp, 3-i)
            self.assertEqual(sth.sha256_root_hash, "hash-%d" % (3-i)) 

        self.assertRaises(StopIteration, generator.next)

    def test_scan_latest_sth_range_honours_log_server(self):
        for i in range(4):
            sth = SthResponse()
            sth.log_server = "test-%d" % i
            sth.timestamp = i
            sth.sha256_root_hash = "hash-%d" % i
            self.db().store_sth(sth)

        for i in range(4):
            generator = self.db().scan_latest_sth_range("test-%d" % i)
            sth = generator.next()
            self.assertEqual(sth.timestamp, i)
            self.assertEqual(sth.sha256_root_hash, "hash-%d" % i)
            self.assertEqual(sth.log_server, "test-%d" % i)

    def test_scan_latest_sth_range_honours_range(self):
        for i in range(4):
            sth = SthResponse()
            sth.log_server = "test"
            sth.timestamp = i
            sth.sha256_root_hash = "hash-%d" % i
            self.db().store_sth(sth)

        generator = self.db().scan_latest_sth_range("test", start=1, end=2)
        for i in range(2):
            sth = generator.next()
            self.assertEqual(sth.log_server, "test")
            self.assertEqual(sth.timestamp, 2-i)
            self.assertEqual(sth.sha256_root_hash, "hash-%d" % (2-i)) 

        self.assertRaises(StopIteration, generator.next)

    def test_scan_latest_sth_range_honours_limit(self):
        for i in range(4):
            sth = SthResponse()
            sth.log_server = "test"
            sth.timestamp = i
            sth.sha256_root_hash = "hash-%d" % i
            self.db().store_sth(sth)

        generator = self.db().scan_latest_sth_range("test", limit=1)
        sth = generator.next()
        self.assertEqual(sth.log_server, "test")
        # Returns most recent
        self.assertEqual(sth.timestamp, 3)
        self.assertEqual(sth.sha256_root_hash, "hash-%d" % 3) 

        self.assertRaises(StopIteration, generator.next)
