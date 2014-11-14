#!/usr/bin/env trial
import copy
import gflags
import logging
import mock
import os
import sys

from ct.client import log_client
from ct.client.db import sqlite_connection as sqlitecon
from ct.client.db import sqlite_log_db
from ct.client.db import sqlite_temp_db
from ct.client import state
from ct.client import monitor
from ct.crypto import error
from ct.crypto import merkle
from ct.crypto import verify
from ct.proto import client_pb2
from twisted.internet import defer
from twisted.trial import unittest
from twisted.web import iweb
from zope.interface import implements

FLAGS = gflags.FLAGS

#TODO(ekasper) to make this setup common to all tests
gflags.DEFINE_bool("verbose_tests", False, "Print test logs")


def dummy_compute_projected_sth(old_sth):
    sth = client_pb2.SthResponse()
    sth.timestamp = old_sth.timestamp
    sth.tree_size = size = old_sth.tree_size
    tree = merkle.CompactMerkleTree(
        merkle.TreeHasher(), size, ["a"] * merkle.count_bits_set(size))
    f = mock.Mock(return_value=(sth, tree))
    f.dummy_sth = sth
    f.dummy_tree = tree
    old_sth.sha256_root_hash = tree.root_hash()
    return f

class FakeEntryProducer(object):
    def __init__(self, start, end, batch_size=None, throw=None):
        self._start = start
        self._end = end
        self._real_start = start
        self._real_end = end
        self.throw = throw
        self.batch_size = batch_size if batch_size else end - start + 1
        self.stop = False

    @defer.deferredGenerator
    def produce(self):
        if self.throw:
            self.done.errback(self.throw)
            return
        for i in range(self._start, self._end, self.batch_size):
            entries = []
            for j in range(i, min(i + self.batch_size, self._end)):
                entry = client_pb2.EntryResponse()
                entry.leaf_input = "leaf_input-%d" % j
                entry.extra_data = "extra_data-%d" % j
                entries.append(entry)
            d = defer.Deferred()
            d.callback(entries)
            wfd = defer.waitForDeferred(d)
            yield wfd
            self.consumer.consume(wfd.getResult())
            if self.stop:
                break

        if not self.stop:
            self.done.callback(self._end - self._start + 1)

    def startProducing(self, consumer):
        self._start = self._real_start
        self._end = self._real_end
        self.consumer = consumer
        self.done = defer.Deferred()
        self.produce()
        return self.done

    def change_range_after_start(self, start, end):
        """Changes query interval exactly when startProducing is ran.

        EntryConsumer in Monitor uses Producer interval, so in one of the tests
        we have to be able to change that interval when producing is started,
        but after consumer is created."""
        self._real_start = start
        self._real_end = end

    def stopProducing(self):
        self.stop = True

class FakeLogClient(object):
    def __init__(self, sth, servername="log_server", batch_size=None,
                 get_entries_throw=None):
        self.servername = servername
        self.sth = sth
        self.batch_size = batch_size
        self.get_entries_throw = get_entries_throw

    def get_sth(self):
        d = defer.Deferred()
        d.callback(self.sth)
        return d

    def get_entries(self, start, end):
        return FakeEntryProducer(start, end, self.batch_size,
                                 self.get_entries_throw)

    def get_sth_consistency(self, old_tree, new_tree):
        d = defer.Deferred()
        d.callback([])
        return d

class InMemoryStateKeeper(object):
    def __init__(self, state=None):
        self.state = state
    def write(self, state):
        self.state = state
    def read(self, state_type):
        if not self.state:
            raise state.FileNotFoundError("Boom!")
        return_state = state_type()
        return_state.CopyFrom(self.state)
        return return_state

class MonitorTest(unittest.TestCase):
    _DEFAULT_STH = client_pb2.SthResponse()
    _DEFAULT_STH.timestamp = 2000
    _DEFAULT_STH.tree_size = 10
    _DEFAULT_STH.tree_head_signature = "sig"
    _DEFAULT_STH_compute_projected = dummy_compute_projected_sth(_DEFAULT_STH)

    _NEW_STH = client_pb2.SthResponse()
    _NEW_STH.timestamp = 3000
    _NEW_STH.tree_size = _DEFAULT_STH.tree_size + 10
    _NEW_STH.tree_head_signature = "sig2"
    _NEW_STH_compute_projected = dummy_compute_projected_sth(_NEW_STH)

    def setUp(self):
        if not FLAGS.verbose_tests:
          logging.disable(logging.CRITICAL)
        self.db = sqlite_log_db.SQLiteLogDB(
            sqlitecon.SQLiteConnectionManager(":memory:", keepalive=True))
        self.temp_db = sqlite_temp_db.SQLiteTempDB(
            sqlitecon.SQLiteConnectionManager(":memory:", keepalive=True))

        default_state = client_pb2.MonitorState()
        default_state.verified_sth.CopyFrom(self._DEFAULT_STH)
        self.state_keeper = InMemoryStateKeeper(default_state)
        self.verifier = mock.Mock()
        self.hasher = merkle.TreeHasher()

        # Make sure the DB knows about the default log server.
        log = client_pb2.CtLogMetadata()
        log.log_server = "log_server"
        self.db.add_log(log)

    def verify_state(self, expected_state):
        self.assertEqual(self.state_keeper.state, expected_state,
            msg="%s== vs ==\n%s" % (self.state_keeper.state, expected_state))

    def verify_tmp_data(self, start, end):
        # TODO: we are no longer using the temp db
        # all the callsites should be updated to test the main db instead
        pass

    def create_monitor(self, client, skip_scan_entry=True):
        m = monitor.Monitor(client, self.verifier, self.hasher, self.db,
                               self.temp_db, self.state_keeper)
        if m:
            m._scan_entries = mock.Mock()
        return m

    def test_update(self):
        client = FakeLogClient(self._NEW_STH)

        m = self.create_monitor(client)
        m._compute_projected_sth_from_tree = self._NEW_STH_compute_projected
        def check_state(result):
            # Check that we wrote the state...
            expected_state = client_pb2.MonitorState()
            expected_state.verified_sth.CopyFrom(self._NEW_STH)
            m._compute_projected_sth_from_tree.dummy_tree.save(
                    expected_state.verified_tree)
            self.verify_state(expected_state)

            self.verify_tmp_data(self._DEFAULT_STH.tree_size,
                                 self._NEW_STH.tree_size-1)
        return m.update().addCallback(self.assertTrue).addCallback(check_state)

    def test_first_update(self):
        client = FakeLogClient(self._DEFAULT_STH)

        self.state_keeper.state = None
        m = self.create_monitor(client)
        m._compute_projected_sth_from_tree = self._DEFAULT_STH_compute_projected
        def check_state(result):
            # Check that we wrote the state...
            expected_state = client_pb2.MonitorState()
            expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
            m._compute_projected_sth_from_tree.dummy_tree.save(
                                                   expected_state.verified_tree)
            self.verify_state(expected_state)

            self.verify_tmp_data(0, self._DEFAULT_STH.tree_size-1)
        d = m.update().addCallback(self.assertTrue
                                   ).addCallback(check_state)
        return d

    def test_update_no_new_entries(self):
        client = FakeLogClient(self._DEFAULT_STH)

        self.temp_db.store_entries = mock.Mock()

        m = self.create_monitor(client)
        d = m.update()
        d.addCallback(self.assertTrue)

        def check_state(result):
            # Check that we kept the state...
            expected_state = client_pb2.MonitorState()
            expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
            self.verify_state(expected_state)

            # ...and wrote no entries.
            self.assertFalse(self.temp_db.store_entries.called)
        d.addCallback(check_state)
        return d

    def test_update_call_sequence(self):
        # Test that update calls update_sth and update_entries in sequence,
        # and bails on first error, so we can test each of them separately.
        # Each of these functions checks if functions were properly called
        # and runs step in sequence of updates.
        def check_calls_sth_fails(result):
            m._update_sth.assert_called_once_with()
            m._update_entries.assert_called_once_with()

            m._update_sth.reset_mock()
            m._update_entries.reset_mock()
            m._update_sth.return_value = copy.deepcopy(d_false)
            return m.update().addCallback(self.assertFalse)

        def check_calls_entries_fail(result):
            m._update_sth.assert_called_once_with()
            self.assertFalse(m._update_entries.called)

            m._update_sth.reset_mock()
            m._update_entries.reset_mock()
            m._update_sth.return_value = copy.deepcopy(d_true)
            m._update_entries.return_value = copy.deepcopy(d_false)
            return m.update().addCallback(self.assertFalse)

        def check_calls_assert_last_calls(result):
            m._update_sth.assert_called_once_with()
            m._update_entries.assert_called_once_with()

        client = FakeLogClient(self._DEFAULT_STH)

        m = self.create_monitor(client)
        d_true = defer.Deferred()
        d_true.callback(True)
        d_false = defer.Deferred()
        d_false.callback(False)
        #check regular correct update
        m._update_sth = mock.Mock(return_value=copy.deepcopy(d_true))
        m._update_entries = mock.Mock(return_value=copy.deepcopy(d_true))
        d = m.update().addCallback(self.assertTrue)
        d.addCallback(check_calls_sth_fails)
        d.addCallback(check_calls_entries_fail)
        d.addCallback(check_calls_assert_last_calls)
        return d

    def test_update_sth(self):
        client = FakeLogClient(self._NEW_STH)

        m = self.create_monitor(client)

        def check_state(result):
            # Check that we updated the state.
            expected_state = client_pb2.MonitorState()
            expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
            expected_state.pending_sth.CopyFrom(self._NEW_STH)
            merkle.CompactMerkleTree().save(expected_state.verified_tree)
            self.verify_state(expected_state)

        return m._update_sth().addCallback(self.assertTrue
                                           ).addCallback(check_state)

    def test_update_sth_fails_for_invalid_sth(self):
        client = FakeLogClient(self._NEW_STH)
        self.verifier.verify_sth.side_effect = error.VerifyError("Boom!")

        m = self.create_monitor(client)
        def check_state(result):
            # Check that we kept the state.
            expected_state = client_pb2.MonitorState()
            expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
            self.verify_state(expected_state)

        return m._update_sth().addCallback(self.assertFalse
                                           ).addCallback(check_state)

    def test_update_sth_fails_for_stale_sth(self):
        sth = client_pb2.SthResponse()
        sth.CopyFrom(self._DEFAULT_STH)
        sth.tree_size -= 1
        sth.timestamp -= 1
        client = FakeLogClient(sth)

        m = self.create_monitor(client)
        d = defer.Deferred()
        d.callback(True)
        m._verify_consistency = mock.Mock(return_value=d)
        def check_state(result):
            self.assertTrue(m._verify_consistency.called)
            args, _ = m._verify_consistency.call_args
            self.assertTrue(args[0].timestamp < args[1].timestamp)

            # Check that we kept the state.
            expected_state = client_pb2.MonitorState()
            expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
            self.verify_state(expected_state)

        return m._update_sth().addCallback(self.assertFalse
                                           ).addCallback(check_state)

    def test_update_sth_fails_for_inconsistent_sth(self):
        client = FakeLogClient(self._NEW_STH)
        # The STH is in fact OK but fake failure.
        self.verifier.verify_sth_consistency.side_effect = (
            error.ConsistencyError("Boom!"))

        m = self.create_monitor(client)
        def check_state(result):
            # Check that we kept the state.
            expected_state = client_pb2.MonitorState()
            expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
            self.verify_state(expected_state)

        return m._update_sth().addCallback(self.assertFalse
                                           ).addCallback(check_state)

    def test_update_sth_fails_on_client_error(self):
        client = FakeLogClient(self._NEW_STH)
        def get_sth():
            return defer.maybeDeferred(mock.Mock(side_effect=log_client.HTTPError("Boom!")))
        client.get_sth = get_sth
        m = self.create_monitor(client)
        def check_state(result):
            # Check that we kept the state.
            expected_state = client_pb2.MonitorState()
            expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
            self.verify_state(expected_state)

        return m._update_sth().addCallback(self.assertFalse
                                           ).addCallback(check_state)


    def test_update_entries_fails_on_client_error(self):
        client = FakeLogClient(self._NEW_STH,
                               get_entries_throw=log_client.HTTPError("Boom!"))
        client.get_entries = mock.Mock(
                return_value=client.get_entries(0, self._NEW_STH.tree_size - 2))
        self.temp_db.store_entries = mock.Mock()

        m = self.create_monitor(client)

        # Get the new STH first.
        d = m._update_sth().addCallback(self.assertTrue)
        d.addCallback(lambda x: m._update_entries().addCallback(self.assertFalse))

        # Check that we wrote no entries.
        d.addCallback(
                lambda x: self.assertFalse(self.temp_db.store_entries.called))
        return d

    def test_update_entries_fails_not_enough_entries(self):
        client = FakeLogClient(self._NEW_STH)
        faker_fake_entry_producer = FakeEntryProducer(0,
                                                      self._NEW_STH.tree_size)
        faker_fake_entry_producer.change_range_after_start(0, 5)
        client.get_entries = mock.Mock(
                return_value=faker_fake_entry_producer)

        m = self.create_monitor(client)
        m._compute_projected_sth = self._NEW_STH_compute_projected
        # Get the new STH first.
        return m._update_sth().addCallback(self.assertTrue).addCallback(
                lambda x: m._update_entries().addCallback(self.assertFalse))

if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
