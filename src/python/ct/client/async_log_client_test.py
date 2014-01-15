#!/usr/bin/env trial

import json
import sys

from ct.client import log_client
from ct.client import log_client_test_util as test_util
import gflags
import mock
from twisted.internet import defer
from twisted.python import failure
from twisted.test import proto_helpers
from twisted.trial import unittest


FLAGS = gflags.FLAGS


class ResponseBodyHandlerTest(unittest.TestCase):
    def test_send(self):
        finished = defer.Deferred()
        handler = log_client.ResponseBodyHandler(finished)
        transport = proto_helpers.StringTransportWithDisconnection()
        handler.makeConnection(transport)
        transport.protocol = handler
        handler.dataReceived("test")
        transport.loseConnection()
        finished.addCallback(self.assertEqual, "test")
        return finished

    def test_send_chunks(self):
        test_msg = "x"*1024
        chunk_size = 100
        finished = defer.Deferred()
        handler = log_client.ResponseBodyHandler(finished)
        transport = proto_helpers.StringTransportWithDisconnection()
        handler.makeConnection(transport)
        transport.protocol = handler
        sent = 0
        while sent < len(test_msg):
            handler.dataReceived(test_msg[sent:sent + chunk_size])
            sent += chunk_size
        transport.loseConnection()
        finished.addCallback(self.assertEqual, test_msg)
        return finished

    def test_buffer_overflow(self):
        original = FLAGS.response_buffer_size_bytes
        FLAGS.response_buffer_size_bytes = 10
        test_msg = "x"*11
        finished = defer.Deferred()
        handler = log_client.ResponseBodyHandler(finished)
        transport = proto_helpers.StringTransportWithDisconnection()
        handler.makeConnection(transport)
        transport.protocol = handler
        handler.dataReceived(test_msg)
        transport.loseConnection()
        # TODO(ekasper): find a more elegant and robust way to save flags.
        FLAGS.response_buffer_size_bytes = original
        return self.assertFailure(finished,
                                  log_client.HTTPResponseSizeExceededError)


class AsyncLogClientTest(unittest.TestCase):
    class FakeHandler(test_util.FakeHandlerBase):

        # A class that mimics twisted.web.iweb.IResponse. Note: the IResponse
        # interface is only partially implemented.
        class FakeResponse(object):
            def __init__(self, code, reason, json_content=None):
                self.code = code
                self.phrase = reason
                if json_content is not None:
                    self._body = json.dumps(json_content)
                else:
                    self._body = ""

            def deliverBody(self, protocol):
                transport = proto_helpers.StringTransportWithDisconnection()
                protocol.makeConnection(transport)
                transport.protocol = protocol
                protocol.dataReceived(self._body)
                transport.loseConnection()

        @classmethod
        def make_response(cls, code, reason, json_content=None):
            return cls.FakeResponse(code, reason, json_content=json_content)

    # Twisted doesn't yet have an official fake Agent:
    # https://twistedmatrix.com/trac/ticket/4024
    class FakeAgent(object):
        def __init__(self, responder):
            self._responder = responder

        def request(self, method, uri):
            if method != "GET":
                return defer.fail(failure.Failure())
            response = self._responder.get_response(uri)
            return defer.succeed(response)

    def one_shot_client(self, json_content):
        """Make a one-shot client and give it a mock response."""
        mock_handler = mock.Mock()
        response = self.FakeHandler.make_response(200, "OK",
                                                  json_content=json_content)
        mock_handler.get_response.return_value = response
        return log_client.AsyncLogClient(self.FakeAgent(mock_handler),
                                         test_util.DEFAULT_URI)

    def default_client(self):
        # A client whose responder is configured to answer queries for the
        # correct uri.
        return log_client.AsyncLogClient(self.FakeAgent(
            self.FakeHandler(test_util.DEFAULT_URI)), test_util.DEFAULT_URI)

    def test_get_sth(self):
        client = self.default_client()
        self.assertEqual(test_util.DEFAULT_STH,
                         self.successResultOf(client.get_sth()))

    def test_get_sth_raises_on_invalid_response(self):
        json_sth = test_util.sth_to_json(test_util.DEFAULT_STH)
        json_sth.pop("timestamp")
        client = self.one_shot_client(json_sth)
        return self.assertFailure(client.get_sth(),
                                  log_client.InvalidResponseError)

    def test_get_sth_raises_on_invalid_base64(self):
        json_sth = test_util.sth_to_json(test_util.DEFAULT_STH)
        json_sth["tree_head_signature"] = "garbagebase64^^^"
        client = self.one_shot_client(json_sth)
        return self.assertFailure(client.get_sth(),
                                  log_client.InvalidResponseError)


if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
