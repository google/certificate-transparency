#!/usr/bin/env python

import gflags
import mock
import requests
import sys
import unittest

from ct.client import log_client
from ct.proto import client_pb2

FLAGS = gflags.FLAGS

# TODO(ekasper): test the Requester class itself with a simple http server.

class LogClientTest(unittest.TestCase):
    # Generate valid-looking responses.
    # We use this class to test the client handles valid responses correctly,
    # and a Mock to test invalid responses.
    class FakeResponder(log_client.Requester):
        def __init__(self, entry_limit=0, log_size_limit=0):
            log_client.Requester.__init__(self, "some_address")
            self.__entry_limit = entry_limit
            self.__log_size_limit = log_size_limit

        def get_json_response(self, path, params={}):
            if path == "ct/v1/get-sth":
                return LogClientTest.sth_to_json(LogClientTest._DEFAULT_STH)
            elif path == "ct/v1/get-entries":
                start = params.get("start", -1)
                end = params.get("end", -1)
                if self.__log_size_limit > 0:
                    end = min(end, self.__log_size_limit - 1)
                if start < 0 or end < 0 or start > end:
                    raise log_client.HTTPClientError("Bad params")
                entries = []
                if self.__entry_limit > 0:
                    end = min(start + self.__entry_limit - 1, end)
                return LogClientTest.entries_to_json(
                    LogClientTest.make_entries(start, end))
            else:
                raise log_client.HTTPError("Bad path %s" % path)

    _DEFAULT_STH = client_pb2.SthResponse()
    _DEFAULT_STH.timestamp = 1234
    _DEFAULT_STH.tree_size = 1000
    _DEFAULT_STH.sha256_root_hash = "hash\x00"
    _DEFAULT_STH.tree_head_signature = "sig\xff"

    @staticmethod
    def make_entries(start, end):
        entries = []
        for i in range(start, end+1):
            entry = client_pb2.EntryResponse()
            entry.leaf_input = "leaf_input-%d" % i
            entry.extra_data = "extra_data-%d" % i
            entries.append(entry)
        return entries

    def verify_entries(self, entries, start, end):
        self.assertEqual(end-start+1, len(entries))
        for i in range(start, end+1):
            self.assertEqual("leaf_input-%d" % i, entries[i].leaf_input)
            self.assertEqual("extra_data-%d" % i, entries[i].extra_data)

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
        mock_request = mock.Mock()
        mock_request.get_json_response.return_value = json_sth
        client = log_client.LogClient(mock_request)
        self.assertRaises(log_client.InvalidResponseError, client.get_sth)

    def test_get_sth_raises_on_invalid_base64(self):
        json_sth = self.sth_to_json(self._DEFAULT_STH)
        json_sth["tree_head_signature"] = "garbagebase64^^^"
        mock_request = mock.Mock()
        mock_request.get_json_response.return_value = json_sth
        client = log_client.LogClient(mock_request)
        self.assertRaises(log_client.InvalidResponseError, client.get_sth)

    def test_get_entries(self):
        client = log_client.LogClient(self.FakeResponder())
        returned_entries = list(client.get_entries(0, 9))
        self.verify_entries(returned_entries, 0, 9)

    def test_get_entries_raises_on_invalid_response(self):
        json_entries = self.entries_to_json(self.make_entries(4, 4))
        json_entries["entries"][0].pop("leaf_input")
        mock_request = mock.Mock()
        mock_request.get_json_response.return_value = json_entries

        client = log_client.LogClient(mock_request)
        entries = client.get_entries(4, 4)
        self.assertRaises(log_client.InvalidResponseError,
                          entries.next)

    def test_get_entries_raises_immediately_on_invalid_base64(self):
        json_entries = self.entries_to_json(self.make_entries(3, 4))
        json_entries["entries"][1]["leaf_input"] = "garbagebase64^^^"
        mock_request = mock.Mock()
        mock_request.get_json_response.return_value = json_entries

        client = log_client.LogClient(mock_request)
        entries = client.get_entries(3, 4)
        # We shouldn't see anything, even if the first entry appeared valid.
        self.assertRaises(log_client.InvalidResponseError,
                          entries.next)

    def test_get_entries_raises_on_empty_response(self):
        mock_request = mock.Mock()
        mock_request.get_json_response.return_value = self.entries_to_json([])

        client = log_client.LogClient(mock_request)
        entries = client.get_entries(4, 4)
        self.assertRaises(log_client.InvalidResponseError,
                          entries.next)

    def test_get_entries_raises_on_too_large_response(self):
        mock_request = mock.Mock()
        mock_request.get_json_response.return_value = self.entries_to_json(
            self.make_entries(4, 5))

        client = log_client.LogClient(mock_request)
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
        client = log_client.LogClient(self.FakeResponder(log_size_limit=3))
        entries = client.get_entries(0, 9)
        partial = []
        for i in range(3):
            partial.append(entries.next())
        self.verify_entries(partial, 0, 2)
        self.assertRaises(log_client.HTTPClientError, entries.next)

if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    unittest.main()
