"""RFC 6962 client API."""
import base64
import json

from ct.proto import client_pb2
import gflags
import requests
from twisted.internet import defer
from twisted.internet import error
from twisted.internet import protocol
from twisted.python import failure
from twisted.web import client
from twisted.web import http


FLAGS = gflags.FLAGS

gflags.DEFINE_integer("entry_fetch_batch_size", 100, "Maximum number of "
                      "entries to attempt to fetch in one request")

gflags.DEFINE_integer("response_buffer_size_bytes", 10 * 1000 * 1000, "Maximum "
                      "size of a single response buffer. Should be set such "
                      "that a get_entries response comfortably fits in the "
                      "the buffer. A typical log entry is expected to be < "
                      "10kB.")


class Error(Exception):
    pass


class ClientError(Error):
    pass


class HTTPError(Error):
    """Connection failed, or returned an error."""
    pass


class HTTPConnectionError(HTTPError):
    """Connection failed."""
    pass


class HTTPResponseSizeExceededError(HTTPError):
    """HTTP response exceeded maximum permitted size."""
    pass


class HTTPClientError(HTTPError):
    """HTTP 4xx."""
    pass


class HTTPServerError(HTTPError):
    """HTTP 5xx."""
    pass


class InvalidRequestError(Error):
    """Request does not comply with the CT protocol."""
    pass


class InvalidResponseError(Error):
    """Response does not comply with the CT protocol."""
    pass


###############################################################################
#                    Common utility methods and constants.                    #
###############################################################################

_GET_STH_PATH = "ct/v1/get-sth"
_GET_ENTRIES_PATH = "ct/v1/get-entries"
_GET_STH_CONSISTENCY_PATH = "ct/v1/get-sth-consistency"
_GET_PROOF_BY_HASH_PATH = "ct/v1/get-proof-by-hash"
_GET_ROOTS_PATH = "ct/v1/get-roots"
_GET_ENTRY_AND_PROOF_PATH = "ct/v1/get-entry-and-proof"


def _parse_sth(sth_body):
    """Parse a serialized STH JSON response."""
    sth_response = client_pb2.SthResponse()
    try:
        sth = json.loads(sth_body)
        sth_response.timestamp = sth["timestamp"]
        sth_response.tree_size = sth["tree_size"]
        sth_response.sha256_root_hash = base64.b64decode(sth[
            "sha256_root_hash"])
        sth_response.tree_head_signature = base64.b64decode(sth[
            "tree_head_signature"])
        # TypeError for base64 decoding, TypeError/ValueError for invalid
        # JSON field types, KeyError for missing JSON fields.
    except (TypeError, ValueError, KeyError) as e:
        raise InvalidResponseError("Invalid STH %s\n%s" % (sth_body, e))
    return sth_response


# A class that we can mock out to generate fake responses.
class RequestHandler(object):
    """HTTPS requests."""

    def __repr__(self):
        return "%r()" % self.__class__.__name__

    def __str__(self):
        return "%r()" % self.__class__.__name__

    def get_response(self, uri, params=None):
        """Get an HTTP response for a GET request."""
        try:
            return requests.get(uri, params=params, timeout=60)
        except requests.exceptions.RequestException as e:
            raise HTTPError("Connection to %s failed: %s" % (uri, e))

    @staticmethod
    def check_response_status(code, reason):
        if code == 200:
            return
        elif 400 <= code < 500:
            raise HTTPClientError(reason)
        elif 500 <= code < 600:
            raise HTTPServerError(reason)
        else:
            raise HTTPError(reason)

    def get_response_body(self, uri, params=None):
        response = self.get_response(uri, params=params)
        self.check_response_status(response.status_code, response.reason)
        return response.content


###############################################################################
#                         The synchronous log client.                         #
###############################################################################


class LogClient(object):
    """HTTP client for talking to a CT log."""

    def __init__(self, uri, handler=RequestHandler()):
        self._uri = uri
        self._req = handler

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self._req)

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, self._req.uri)

    @property
    def servername(self):
        return self._uri

    def _req_body(self, path, params=None):
        return self._req.get_response_body("https://" + self._uri + "/" + path,
                                           params=params)

    def get_sth(self):
        """Get the current Signed Tree Head.

        Returns:
            a ct.proto.client_pb2.SthResponse proto.

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed.
                For logs that honour HTTP status codes, HTTPClientError (a 4xx)
                should never happen.
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        sth = self._req_body(_GET_STH_PATH)
        return _parse_sth(sth)

    def _json_entry_to_response(self, json_entry):
        """Convert a json array element to an EntryResponse."""
        entry_response = client_pb2.EntryResponse()
        try:
            entry_response.leaf_input = base64.b64decode(
                json_entry["leaf_input"])
            entry_response.extra_data = base64.b64decode(
                json_entry["extra_data"])
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected a log entry, got %s"
                "\n%s" % (self.servername, json_entry, e))
        return entry_response

    def _validated_entry_response(self, start, end, response):
        """Verify the get-entries response format and size.

        Args:
            start: requested start parameter.
            end:  requested end parameter.
            response: response.

        Returns:
            an array of entries.

        Raises:
            InvalidResponseError: response not valid.
        """
        entries = None
        try:
            response = json.loads(response)
        except ValueError:
            raise InvalidResponseError()
        try:
            entries = iter(response["entries"])
        except (TypeError, KeyError) as e:
            raise InvalidResponseError("%s returned invalid data: expected "
                                       "an array of entries, got %s\n%s)" %
                                       (self._uri, response, e))
        expected_response_size = end - start + 1
        response_size = len(response["entries"])
        # Logs MAY honor requests where 0 <= "start" < "tree_size" and
        # "end" >= "tree_size" by returning a partial response covering only
        # the valid entries in the specified range.
        # Logs MAY restrict the number of entries that can be retrieved per
        # "get-entries" request.  If a client requests more than the
        # permitted number of entries, the log SHALL return the maximum
        # number of entries permissible. (RFC 6962)
        #
        # Therefore, we cannot assume we get exactly the expected number of
        # entries. However if we get none, or get more than expected, then
        # we discard the response and raise.
        if not response_size or response_size > expected_response_size:
            raise InvalidResponseError(
                "%s returned invalid data: requested %d entries, got %d "
                "entries" % (self.servername, expected_response_size,
                             response_size))

        # If any one of the entries has invalid json format, this raises.
        return [self._json_entry_to_response(e) for e in entries]

    def get_entries(self, start, end, batch_size=0):
        """Retrieve log entries.

        Args:
            start     : index of first entry to retrieve.
            end       : index of last entry to retrieve.
            batch_size: max number of entries to fetch in one go.

        Yields:
            ct.proto.client_pb2.EntryResponse protos.

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
                or returned an error. HTTPClientError can happen when
                [start, end] is not a valid range for this log.
            InvalidRequestError: invalid request range (irrespective of log).
            InvalidResponseError: server response is invalid for the given
                                  request
        Caller is responsible for ensuring that (start, end) is a valid range
        (by retrieving an STH first), otherwise a HTTPClientError may occur.
        """
        # Catch obvious mistakes here.
        if start < 0 or end < 0 or start > end:
            raise InvalidRequestError("Invalid range [%d, %d]" % (start, end))

        batch_size = batch_size or FLAGS.entry_fetch_batch_size
        while start <= end:
            # Note that an HTTPError may occur here if the log does not have the
            # requested range of entries available. RFC 6962 says:
            # "Any errors will be returned as HTTP 4xx or 5xx responses, with
            # human-readable error messages."
            # There is thus no easy way to distinguish this case from other
            # errors.
            first = start
            last = min(start + batch_size - 1, end)
            response = self._req_body(_GET_ENTRIES_PATH,
                                      params={"start": first, "end": last})
            valid_entries = self._validated_entry_response(first, last,
                                                           response)
            for entry in valid_entries:
                yield entry
            # If we got less entries than requested, then we don't know whether
            # the log imposed a batch limit or ran out of entries, so we keep
            # trying until we get all entries, or an error response.
            start += len(valid_entries)

    def get_sth_consistency(self, old_size, new_size):
        """Retrieve a consistency proof.

        Args:
            old_size  : size of older tree.
            new_size  : size of newer tree.

        Returns:
            list of raw hashes (bytes) forming the consistency proof

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
                or returned an error. HTTPClientError can happen when
                (old_size, new_size) are not valid for this log (e.g. greater
                than the size of the log).
            InvalidRequestError: invalid request size (irrespective of log).
            InvalidResponseError: server response is invalid for the given
                                  request
        Caller is responsible for ensuring that (old_size, new_size) are valid
        (by retrieving an STH first), otherwise a HTTPClientError may occur.
        """
        if old_size > new_size:
            raise InvalidRequestError(
                "old > new: %s >= %s" % (old_size, new_size))

        if old_size < 0 or new_size < 0:
            raise InvalidRequestError(
                "both sizes must be >= 0: %s, %s" % (old_size, new_size))

        # don't need to contact remote server for trivial proofs:
        # - empty tree is consistent with everything
        # - everything is consistent with itself
        if old_size == 0 or old_size == new_size:
            return []

        response = self._req_body(_GET_STH_CONSISTENCY_PATH,
                                  params={"first": old_size,
                                          "second": new_size})

        try:
            response = json.loads(response)
            consistency = [base64.b64decode(u) for u in response["consistency"]]
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected a base64-encoded "
                "consistency proof, got %s"
                "\n%s" % (self.servername, response, e))

        return consistency

    def get_proof_by_hash(self, leaf_hash, tree_size):
        """Retrieve an audit proof by leaf hash.

        Args:
            leaf_hash: hash of the leaf input (as raw binary string).
            tree_size: size of the tree on which to base the proof.

        Returns:
            a client_pb2.ProofByHashResponse containing the leaf index
            and the Merkle tree audit path nodes (as binary strings).

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
            HTTPClientError can happen when leaf_hash is not present in the
                log tree of the given size.
            InvalidRequestError: invalid request (irrespective of log).
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        if tree_size <= 0:
            raise InvalidRequestError("Tree size must be positive (got %d)" %
                                      tree_size)

        leaf_hash = base64.b64encode(leaf_hash)
        response = self._req_body(_GET_PROOF_BY_HASH_PATH,
                                  params={"hash": leaf_hash,
                                          "tree_size": tree_size})
        response = json.loads(response)

        proof_response = client_pb2.ProofByHashResponse()
        try:
            proof_response.leaf_index = response["leaf_index"]
            proof_response.audit_path.extend(
                [base64.b64decode(u) for u in response["audit_path"]])
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected a base64-encoded "
                "audit proof, got %s"
                "\n%s" % (self.servername, response, e))

        return proof_response

    def get_entry_and_proof(self, leaf_index, tree_size):
        """Retrieve an entry and its audit proof by index.

        Args:
            leaf_index: index of the entry.
            tree_size: size of the tree on which to base the proof.

        Returns:
            a client_pb2.EntryAndProofResponse containing the entry
            and the Merkle tree audit path nodes (as binary strings).

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
            HTTPClientError can happen when tree_size is not a valid size
                for this log.
            InvalidRequestError: invalid request (irrespective of log).
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        if tree_size <= 0:
            raise InvalidRequestError("Tree size must be positive (got %d)" %
                                      tree_size)

        if leaf_index < 0 or leaf_index >= tree_size:
            raise InvalidRequestError("Leaf index must be smaller than tree "
                                      "size (got index %d vs size %d" %
                                      (leaf_index, tree_size))

        response = self._req_body(_GET_ENTRY_AND_PROOF_PATH,
                                  params={"leaf_index": leaf_index,
                                          "tree_size": tree_size})
        response = json.loads(response)

        entry_response = client_pb2.EntryAndProofResponse()
        try:
            entry_response.entry.CopyFrom(
                self._json_entry_to_response(response))
            entry_response.audit_path.extend(
                [base64.b64decode(u) for u in response["audit_path"]])
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected an entry and proof, got %s"
                "\n%s" % (self.servername, response, e))

        return entry_response

    def get_roots(self):
        """Retrieve currently accepted root certificates.

        Returns:
            a list of certificates (as raw binary strings).

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed,
                or returned an error. For logs that honour HTTP status codes,
                HTTPClientError (a 4xx) should never happen.
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        response = self._req_body(_GET_ROOTS_PATH)
        response = json.loads(response)
        try:
            return [base64.b64decode(u)for u in response["certificates"]]
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError(
                "%s returned invalid data: expected a list od base64-encoded "
                "certificates, got %s\n%s" % (self.servername, response, e))


###############################################################################
#                       The asynchronous twisted log client.                  #
###############################################################################


class ResponseBodyHandler(protocol.Protocol):
    """Response handler for HTTP requests."""
    def __init__(self, finished):
        """Initialize the one-off response handler.

        Args:
            finished: a deferred that will be fired with the body when the
                complete response has been received; or with an error when the
                connection is lost.
        """
        self._finished = finished

    def connectionMade(self):
        self._buffer = []
        self._len = 0
        self._overflow = False

    def dataReceived(self, data):
        self._len += len(data)
        if self._len > FLAGS.response_buffer_size_bytes:
            # Note this flag has to be set *before* calling loseConnection()
            # to ensure connectionLost gets called with the flag set.
            self._overflow = True
            self.transport.loseConnection()
        else:
            self._buffer.append(data)

    def connectionLost(self, reason):
        if self._overflow:
            self._finished.errback(HTTPResponseSizeExceededError(
                "Connection aborted: response size exceeded %d bytes" %
                FLAGS.response_buffer_size_bytes))
        elif not reason.check(*(error.ConnectionDone, client.ResponseDone,
                                http.PotentialDataLoss)):
            self._finished.errback(HTTPConnectionError(
                "Connection lost (received %d bytes)" % self._len))
        else:
            body = "".join(self._buffer)
            self._finished.callback(body)


class AsyncLogClient(object):
    """A twisted log client."""
    def __init__(self, agent, uri):
        """Initialize the client.

        Args:
            agent: a twisted.web.client.Agent.
            uri: the uri of the log.
        """
        self._uri = uri
        self._agent = agent

    @property
    def servername(self):
        return self._uri

    @staticmethod
    def _response_cb(response):
        try:
            RequestHandler.check_response_status(response.code, response.phrase)
        except HTTPError as e:
            return failure.Failure(e)
        finished = defer.Deferred()
        response.deliverBody(ResponseBodyHandler(finished))
        return finished

    def get_sth(self):
        """Get the current Signed Tree Head.

        Returns:
            a Deferred that fires with a ct.proto.client_pb2.SthResponse proto.

        Raises:
            HTTPError, HTTPConnectionError, HTTPClientError,
            HTTPResponseSizeExceededError, HTTPServerError: connection failed.
                For logs that honour HTTP status codes, HTTPClientError (a 4xx)
                should never happen.
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        deferred_result = self._agent.request(
            "GET", "https://" + self._uri + "/" + _GET_STH_PATH)
        deferred_result.addCallback(self._response_cb)
        # Since _response_cb returns a deferred, the processing of
        # |deferred_result| will stop until the returned deferred has fired, and
        # resume with the result, see
        # http://twistedmatrix.com/documents/current/core/howto/defer.html#auto18
        deferred_result.addCallback(_parse_sth)
        return deferred_result
