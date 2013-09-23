#!/usr/bin/env python

import sys
import unittest

from ct.client import log_client
from ct.crypto import merkle
from ct.proto import client_pb2
import gflags
import mock

FLAGS = gflags.FLAGS

# TODO(ekasper): test the Requester class itself with a simple http server.


class LogClientTest(unittest.TestCase):

    # Generate valid-looking responses.
    # We use this class to test the client handles valid responses correctly,
    # and a Mock to test invalid responses.
    class FakeResponder(log_client.Requester):
        def __init__(self, entry_limit=0, tree_size=0):
            log_client.Requester.__init__(self, "some_address")
            self.__entry_limit = entry_limit

            self.__sth = LogClientTest._DEFAULT_STH
            # Override with custom size
            if tree_size > 0:
              self.__sth.tree_size = tree_size

        def get_json_response(self, path, params=None):
            if params is None:
                params = {}
            if path == "ct/v1/get-sth":
                return LogClientTest.sth_to_json(self.__sth)
            elif path == "ct/v1/get-entries":
                start = params.get("start", -1)
                end = params.get("end", -1)
                end = min(end, self.__sth.tree_size - 1)
                if start < 0 or end < 0 or start > end:
                    raise log_client.HTTPClientError("Bad params")
                if self.__entry_limit > 0:
                    end = min(start + self.__entry_limit - 1, end)
                return LogClientTest.entries_to_json(
                    LogClientTest.make_entries(start, end))
            elif path == "ct/v1/get-sth-consistency":
                old_size = params.get("first", -1)
                new_size = params.get("second", -1)
                if not 0 <= old_size <= new_size <= self.__sth.tree_size:
                    raise log_client.HTTPClientError("Bad params")
                return LogClientTest.consistency_proof_to_json(
                    LogClientTest._DEFAULT_FAKE_PROOF)
            elif path == "ct/v1/get-roots":
                return LogClientTest.roots_to_json(
                    LogClientTest._DEFAULT_FAKE_ROOTS)
            elif path == "ct/v1/get-entry-and-proof":
                leaf_index = params.get("leaf_index", -1)
                tree_size = params.get("tree_size", -1)
                if (leaf_index >= tree_size or leaf_index < 0 or tree_size <= 0
                    or tree_size > self.__sth.tree_size):
                    raise log_client.HTTPClientError("Bad params")
                return LogClientTest.entry_and_proof_to_json(
                    LogClientTest.make_entry(leaf_index),
                    LogClientTest._DEFAULT_FAKE_PROOF)
            elif path == "ct/v1/get-proof-by-hash":
                leaf_hash = params.get("hash", "").decode("base64")
                tree_size = params.get("tree_size", -1)
                if (not leaf_hash or tree_size <= 0 or
                    tree_size > self.__sth.tree_size):
                    raise log_client.HTTPClientError("Bad params")
                hasher = merkle.TreeHasher()
                for i in range(self.__sth.tree_size):
                    entry = LogClientTest.make_entry(i)
                    if hasher.hash_leaf(entry.leaf_input) == leaf_hash:
                      return LogClientTest.proof_and_index_to_json(
                          LogClientTest._DEFAULT_FAKE_PROOF, i)
                # Not found
                raise log_client.HTTPClientError("Not found")
            else:
                raise log_client.HTTPError("Bad path %s" % path)

    _DEFAULT_STH = client_pb2.SthResponse()
    _DEFAULT_STH.timestamp = 1234
    _DEFAULT_STH.tree_size = 1000
    _DEFAULT_STH.sha256_root_hash = "hash\x00"
    _DEFAULT_STH.tree_head_signature = "sig\xff"
    _DEFAULT_FAKE_PROOF = [(c*32) for c in "abc"]
    _DEFAULT_FAKE_ROOTS = [("cert-%d" % i) for i in range(4)]

    @staticmethod
    def make_entry(leaf_index):
        entry = client_pb2.EntryResponse()
        entry.leaf_input = "leaf_input-%d" % leaf_index
        entry.extra_data = "extra_data-%d" % leaf_index
        return entry

    @staticmethod
    def make_entries(start, end):
        entries = []
        for i in range(start, end+1):
            entries.append(LogClientTest.make_entry(i))
        return entries

    def verify_entries(self, entries, start, end):
        self.assertEqual(end-start+1, len(entries))
        for i in range(start, end+1):
            self.assertEqual(LogClientTest.make_entry(i), entries[i])

    @staticmethod
    def sth_to_json(sth):
        return {"timestamp": sth.timestamp, "tree_size": sth.tree_size,
                "sha256_root_hash": sth.sha256_root_hash.encode("base64"),
                "tree_head_signature": sth.tree_head_signature.encode("base64")}

    @staticmethod
    def entries_to_json(entries):
        return {"entries": [{"leaf_input": entry.leaf_input.encode("base64"),
                             "extra_data": entry.extra_data.encode("base64")}
                            for entry in entries]}

    @staticmethod
    def consistency_proof_to_json(hashes):
        return {"consistency": [h.encode("base64") for h in hashes]}

    @staticmethod
    def roots_to_json(roots):
        return {"certificates": [r.encode("base64") for r in roots]}

    @staticmethod
    def entry_and_proof_to_json(entry, proof):
        return {"leaf_input": entry.leaf_input.encode("base64"),
                "extra_data": entry.extra_data.encode("base64"),
                "audit_path": [h.encode("base64") for h in proof]}

    @staticmethod
    def proof_and_index_to_json(proof, leaf_index):
        return {"leaf_index": leaf_index,
                "audit_path": [h.encode("base64") for h in proof]}

    @staticmethod
    def one_shot_client(response=None):
        """Make a one-shot client and give it a mock response."""
        if response is None:
            response = {}
        mock_request = mock.Mock()
        mock_request.get_json_response.return_value = response
        return log_client.LogClient(mock_request)

    def test_get_sth(self):
        client = log_client.LogClient(self.FakeResponder())
        sth_response = client.get_sth()

        self.assertEqual(sth_response.timestamp, self._DEFAULT_STH.timestamp)
        self.assertEqual(sth_response.tree_size, self._DEFAULT_STH.tree_size)
        self.assertEqual(sth_response.sha256_root_hash,
                         self._DEFAULT_STH.sha256_root_hash)
        self.assertEqual(sth_response.tree_head_signature,
                         self._DEFAULT_STH.tree_head_signature)

    def test_get_sth_raises_on_invalid_response(self):
        json_sth = self.sth_to_json(self._DEFAULT_STH)
        json_sth.pop("timestamp")
        client = self.one_shot_client(json_sth)
        self.assertRaises(log_client.InvalidResponseError, client.get_sth)

    def test_get_sth_raises_on_invalid_base64(self):
        json_sth = self.sth_to_json(self._DEFAULT_STH)
        json_sth["tree_head_signature"] = "garbagebase64^^^"
        mock_request = mock.Mock()
        mock_request.get_json_response.return_value = json_sth
        client = self.one_shot_client(mock_request)
        self.assertRaises(log_client.InvalidResponseError, client.get_sth)

    def test_get_entries(self):
        client = log_client.LogClient(self.FakeResponder())
        returned_entries = list(client.get_entries(0, 9))
        self.verify_entries(returned_entries, 0, 9)

    def test_get_entries_raises_on_invalid_response(self):
        json_entries = self.entries_to_json(self.make_entries(4, 4))
        json_entries["entries"][0].pop("leaf_input")

        client = self.one_shot_client(json_entries)
        entries = client.get_entries(4, 4)
        self.assertRaises(log_client.InvalidResponseError,
                          entries.next)

    def test_get_entries_raises_immediately_on_invalid_base64(self):
        json_entries = self.entries_to_json(self.make_entries(3, 4))
        json_entries["entries"][1]["leaf_input"] = "garbagebase64^^^"

        client = self.one_shot_client(json_entries)
        entries = client.get_entries(3, 4)
        # We shouldn't see anything, even if the first entry appeared valid.
        self.assertRaises(log_client.InvalidResponseError,
                          entries.next)

    def test_get_entries_raises_on_empty_response(self):
        empty_entries = self.entries_to_json([])
        client = self.one_shot_client(empty_entries)

        entries = client.get_entries(4, 4)
        self.assertRaises(log_client.InvalidResponseError,
                          entries.next)

    def test_get_entries_raises_on_too_large_response(self):
        large_response = self.entries_to_json(
            self.make_entries(4, 5))

        client = self.one_shot_client(large_response)
        entries = client.get_entries(4, 4)
        self.assertRaises(log_client.InvalidResponseError,
                          entries.next)

    def test_get_entries_returns_all_in_batches(self):
        mock_responder = mock.Mock()
        fake_responder = self.FakeResponder()
        mock_responder.get_json_response.side_effect = (
            fake_responder.get_json_response)

        client = log_client.LogClient(mock_responder)
        returned_entries = list(client.get_entries(0, 9, batch_size=4))
        self.verify_entries(returned_entries, 0, 9)
        self.assertEqual(3, len(mock_responder.get_json_response.
                                call_args_list))

        # Same as above, but using a flag to control the batch size.
        mock_responder.reset_mock()
        FLAGS.entry_fetch_batch_size = 4
        returned_entries = list(client.get_entries(0, 9))
        self.verify_entries(returned_entries, 0, 9)
        self.assertEqual(3, len(mock_responder.get_json_response.
                                call_args_list))

    def test_get_entries_returns_all_for_limiting_server(self):
        client = log_client.LogClient(self.FakeResponder(entry_limit=3))
        returned_entries = list(client.get_entries(0, 9))
        self.verify_entries(returned_entries, 0, 9)

    def test_get_entries_returns_partial_if_log_returns_partial(self):
        client = log_client.LogClient(self.FakeResponder(tree_size=3))
        entries = client.get_entries(0, 9)
        partial = []
        for _ in range(3):
            partial.append(entries.next())
        self.verify_entries(partial, 0, 2)
        self.assertRaises(log_client.HTTPClientError, entries.next)

    def test_get_sth_consistency(self):
        client = log_client.LogClient(self.FakeResponder(tree_size=3))
        proof = client.get_sth_consistency(1, 2)
        self.assertEqual(proof, LogClientTest._DEFAULT_FAKE_PROOF)

    def test_get_sth_consistency_trivial(self):
        client = log_client.LogClient(self.FakeResponder(tree_size=3))
        self.assertEqual(client.get_sth_consistency(0, 0), [])
        self.assertEqual(client.get_sth_consistency(0, 2), [])
        self.assertEqual(client.get_sth_consistency(2, 2), [])

    def test_get_sth_consistency_raises_on_invalid_input(self):
        client = log_client.LogClient(self.FakeResponder(tree_size=3))
        self.assertRaises(log_client.InvalidRequestError,
                          client.get_sth_consistency, -1, 1)
        self.assertRaises(log_client.InvalidRequestError,
                          client.get_sth_consistency, -3, -1)
        self.assertRaises(log_client.InvalidRequestError,
                          client.get_sth_consistency, 3, 1)

    def test_get_sth_consistency_raises_on_client_error(self):
        client = log_client.LogClient(self.FakeResponder(tree_size=3))
        self.assertRaises(log_client.HTTPClientError,
                          client.get_sth_consistency, 1, 5)

    def test_get_sth_consistency_raises_on_invalid_response(self):
        client = self.one_shot_client()
        self.assertRaises(log_client.InvalidResponseError,
                          client.get_sth_consistency, 1, 2)

    def test_get_sth_consistency_raises_on_invalid_base64(self):
        json_proof = {"consistency": ["garbagebase64^^^"]}
        client = self.one_shot_client(json_proof)
        self.assertRaises(log_client.InvalidResponseError,
                          client.get_sth_consistency, 1, 2)

    def test_get_roots(self):
        client = log_client.LogClient(self.FakeResponder())
        roots = client.get_roots()
        self.assertEqual(roots, self._DEFAULT_FAKE_ROOTS)

    def test_get_roots_raises_on_invalid_response(self):
        client = self.one_shot_client()
        self.assertRaises(log_client.InvalidResponseError,
                          client.get_roots)

    def test_get_roots_raises_on_invalid_base64(self):
        json_roots = {"certificates": ["garbagebase64^^^"]}
        client = self.one_shot_client(json_roots)
        self.assertRaises(log_client.InvalidResponseError,
                          client.get_roots)

    def test_get_entry_and_proof(self):
        client = log_client.LogClient(self.FakeResponder())
        entry_and_proof = client.get_entry_and_proof(1, 2)
        self.assertEqual(entry_and_proof.entry, LogClientTest.make_entry(1))
        self.assertEqual(entry_and_proof.audit_path,
                         LogClientTest._DEFAULT_FAKE_PROOF)

    def test_get_entry_and_proof_raises_on_invalid_input(self):
        client = log_client.LogClient(self.FakeResponder())
        self.assertRaises(log_client.InvalidRequestError,
                          client.get_entry_and_proof, -1, 1)
        self.assertRaises(log_client.InvalidRequestError,
                          client.get_entry_and_proof, -3, -1)
        self.assertRaises(log_client.InvalidRequestError,
                          client.get_entry_and_proof, 3, 1)

    def test_get_entry_and_proof_raises_on_client_error(self):
        client = log_client.LogClient(self.FakeResponder(tree_size=3))
        self.assertRaises(log_client.HTTPClientError,
                          client.get_entry_and_proof, 1, 5)

    def test_get_entry_and_proof_raises_on_invalid_response(self):
        json_response = self.entry_and_proof_to_json(self.make_entry(1),
                                                     self._DEFAULT_FAKE_PROOF)
        json_response.pop("leaf_input")
        client = self.one_shot_client(json_response)
        self.assertRaises(log_client.InvalidResponseError,
                          client.get_entry_and_proof, 1, 2)

    def test_get_entry_and_proof_raises_on_invalid_base64(self):
        json_response = self.entry_and_proof_to_json(self.make_entry(1),
                                                     self._DEFAULT_FAKE_PROOF)
        json_response["leaf_input"] = ["garbagebase64^^^"]
        client = self.one_shot_client(json_response)
        self.assertRaises(log_client.InvalidResponseError,
                          client.get_entry_and_proof, 1, 2)

    def test_get_proof_by_hash(self):
        client = log_client.LogClient(self.FakeResponder())
        entry = self.make_entry(1)
        hasher = merkle.TreeHasher()
        leaf_hash = hasher.hash_leaf(entry.leaf_input)

        proof_by_hash = client.get_proof_by_hash(leaf_hash, 2)
        self.assertEqual(proof_by_hash.audit_path,
                         LogClientTest._DEFAULT_FAKE_PROOF)
        self.assertEqual(proof_by_hash.leaf_index, 1)

    def test_get_proof_by_hash_raises_on_invalid_input(self):
        client = log_client.LogClient(self.FakeResponder())
        leaf_hash = "hash"
        self.assertRaises(log_client.InvalidRequestError,
                          client.get_proof_by_hash, leaf_hash, 0)
        self.assertRaises(log_client.InvalidRequestError,
                          client.get_proof_by_hash, leaf_hash, -1)

    def test_get_proof_by_hash_raises_on_unknown_hash(self):
        client = log_client.LogClient(self.FakeResponder(tree_size=3))
        leaf_hash = "bogus"
        self.assertRaises(log_client.HTTPClientError,
                          client.get_proof_by_hash, leaf_hash, 2)

    def test_get_proof_by_hash_raises_on_invalid_response(self):
        json_response = self.proof_and_index_to_json(self._DEFAULT_FAKE_PROOF,
                                                     1)
        json_response.pop("leaf_index")
        client = self.one_shot_client(json_response)
        self.assertRaises(log_client.InvalidResponseError,
                          client.get_proof_by_hash, "hash", 2)

    def test_get_proof_by_hash_raises_on_invalid_base64(self):
        json_response = self.proof_and_index_to_json(self._DEFAULT_FAKE_PROOF,
                                                     1)
        json_response["leaf_index"] = "garbagebase64^^^"
        client = self.one_shot_client(json_response)
        self.assertRaises(log_client.InvalidResponseError,
                          client.get_proof_by_hash, "hash", 2)

if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    unittest.main()
