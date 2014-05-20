#!/usr/bin/env python
import gflags
import logging
import mock
import os
import sys
import unittest

from ct.client import log_client
from ct.client import sqlite_connection as sqlitecon
from ct.client import sqlite_log_db
from ct.client import sqlite_temp_db
from ct.client import state
from ct.client import monitor
from ct.crypto import error
from ct.crypto import merkle
from ct.crypto import verify
from ct.proto import client_pb2

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


class FakeLogClient(object):
    def __init__(self, sth, servername="log_server"):
        self.servername = servername
        self.sth = sth

    def get_sth(self):
        return self.sth

    def get_entries(self, start, end):
        for i in range(start, min(self.sth.tree_size, end+1)):
            entry = client_pb2.EntryResponse()
            entry.leaf_input = "leaf_input-%d" % i
            entry.extra_data = "extra_data-%d" % i
            yield entry

    def get_sth_consistency(self, old_tree, new_tree):
        return []

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

    def create_monitor(self, client):
        return monitor.Monitor(client, self.verifier, self.hasher, self.db,
                               self.temp_db, self.state_keeper)

    def test_update(self):
        client = FakeLogClient(self._NEW_STH)

        m = self.create_monitor(client)
        m._compute_projected_sth = self._NEW_STH_compute_projected
        self.assertTrue(m.update())

        # Check that we wrote the state...
        expected_state = client_pb2.MonitorState()
        expected_state.verified_sth.CopyFrom(self._NEW_STH)
        m._compute_projected_sth.dummy_tree.save(expected_state.verified_tree)
        self.verify_state(expected_state)

        self.verify_tmp_data(self._DEFAULT_STH.tree_size,
                             self._NEW_STH.tree_size-1)

    def test_first_update(self):
        client = FakeLogClient(self._DEFAULT_STH)

        self.state_keeper.state = None
        m = self.create_monitor(client)
        m._compute_projected_sth = self._DEFAULT_STH_compute_projected
        self.assertTrue(m.update())

        # Check that we wrote the state...
        expected_state = client_pb2.MonitorState()
        expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
        m._compute_projected_sth.dummy_tree.save(expected_state.verified_tree)
        self.verify_state(expected_state)

        self.verify_tmp_data(0, self._DEFAULT_STH.tree_size-1)

    def test_update_no_new_entries(self):
        client = FakeLogClient(self._DEFAULT_STH)

        self.temp_db.store_entries = mock.Mock()

        m = self.create_monitor(client)
        self.assertTrue(m.update())

        # Check that we kept the state...
        expected_state = client_pb2.MonitorState()
        expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
        self.verify_state(expected_state)

        # ...and wrote no entries.
        self.assertFalse(self.temp_db.store_entries.called)

    def test_update_call_sequence(self):
        # Test that update calls update_sth and update_entries in sequence,
        # and bails on first error, so we can test each of them separately.
        client = FakeLogClient(self._DEFAULT_STH)

        m = self.create_monitor(client)
        m._update_sth = mock.Mock(return_value=True)
        m._update_entries = mock.Mock(return_value=True)
        self.assertTrue(m.update())
        m._update_sth.assert_called_once_with()
        m._update_entries.assert_called_once_with()

        m._update_sth.reset_mock()
        m._update_entries.reset_mock()
        m._update_sth.return_value = False
        self.assertFalse(m.update())
        m._update_sth.assert_called_once_with()
        self.assertFalse(m._update_entries.called)

        m._update_sth.reset_mock()
        m._update_entries.reset_mock()
        m._update_sth.return_value = True
        m._update_entries.return_value = False
        self.assertFalse(m.update())
        m._update_sth.assert_called_once_with()
        m._update_entries.assert_called_once_with()

    def test_update_sth(self):
        client = FakeLogClient(self._NEW_STH)

        m = self.create_monitor(client)
        self.assertTrue(m._update_sth())

        # Check that we updated the state.
        expected_state = client_pb2.MonitorState()
        expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
        expected_state.pending_sth.CopyFrom(self._NEW_STH)
        merkle.CompactMerkleTree().save(expected_state.verified_tree)
        self.verify_state(expected_state)

    def test_update_sth_fails_for_invalid_sth(self):
        client = FakeLogClient(self._NEW_STH)
        self.verifier.verify_sth.side_effect = error.VerifyError("Boom!")

        m = self.create_monitor(client)
        self.assertFalse(m._update_sth())

        # Check that we kept the state.
        expected_state = client_pb2.MonitorState()
        expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
        self.verify_state(expected_state)

    def test_update_sth_fails_for_stale_sth(self):
        sth = client_pb2.SthResponse()
        sth.CopyFrom(self._DEFAULT_STH)
        sth.tree_size -= 1
        sth.timestamp -= 1
        client = FakeLogClient(sth)

        m = self.create_monitor(client)
        self.assertFalse(m._update_sth())

        # Check that we kept the state.
        expected_state = client_pb2.MonitorState()
        expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
        self.verify_state(expected_state)

    def test_update_sth_fails_for_inconsistent_sth(self):
        client = FakeLogClient(self._NEW_STH)
        # The STH is in fact OK but fake failure.
        self.verifier.verify_sth_consistency.side_effect = (
            error.ConsistencyError("Boom!"))

        m = self.create_monitor(client)
        self.assertFalse(m._update_sth())

        # Check that we kept the state.
        expected_state = client_pb2.MonitorState()
        expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
        self.verify_state(expected_state)

    def test_update_sth_fails_on_client_error(self):
        client = FakeLogClient(self._NEW_STH)
        client.get_sth = mock.Mock(side_effect=log_client.HTTPError("Boom!"))

        m = self.create_monitor(client)
        self.assertFalse(m._update_sth())

        # Check that we kept the state.
        expected_state = client_pb2.MonitorState()
        expected_state.verified_sth.CopyFrom(self._DEFAULT_STH)
        self.verify_state(expected_state)

    def test_update_entries_fails_on_client_error(self):
        client = FakeLogClient(self._NEW_STH)
        client.get_entries = mock.MagicMock()
        client.get_entries.next.side_effect=log_client.HTTPError("Boom!")
        self.temp_db.store_entries = mock.Mock()

        m = self.create_monitor(client)
        # Get the new STH first.
        self.assertTrue(m._update_sth())
        self.assertFalse(m._update_entries())

        # Check that we wrote no entries.
        self.assertFalse(self.temp_db.store_entries.called)

    def test_update_entries_fails_not_enough_entries(self):
        client = FakeLogClient(self._NEW_STH)
        client.get_entries = mock.MagicMock()
        entry = client_pb2.EntryResponse()
        entry.leaf_input = "leaf"
        entry.extra_data = "extra"
        client.get_entries.return_value = iter([entry])

        m = self.create_monitor(client)
        m._compute_projected_sth = self._NEW_STH_compute_projected
        # Get the new STH first.
        self.assertTrue(m._update_sth())

        self.assertFalse(m._update_entries())

if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    unittest.main()
