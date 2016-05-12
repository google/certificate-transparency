"""RFC 6962 client API."""
import base64
import json

from ct.crypto import verify
from ct.proto import client_pb2
import gflags
import logging
import requests
import urllib
import urlparse

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("entry_fetch_batch_size", 1000, "Maximum number of "
                      "entries to attempt to fetch in one request.")

gflags.DEFINE_integer("get_entries_max_retries", 10, "Number of retries after "
                      "which get-entries simply fails.")


class Error(Exception):
    pass


class ClientError(Error):
    pass


class HTTPError(Error):
    """Connection failed, or returned an error."""
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
_ADD_CHAIN = "ct/v1/add-chain"


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


def _parse_entry(json_entry):
    """Convert a json array element to an EntryResponse."""
    entry_response = client_pb2.EntryResponse()
    try:
        entry_response.leaf_input = base64.b64decode(
            json_entry["leaf_input"])
        entry_response.extra_data = base64.b64decode(
            json_entry["extra_data"])
    except (TypeError, ValueError, KeyError) as e:
        raise InvalidResponseError("Invalid entry: %s\n%s" % (json_entry, e))
    return entry_response


def _parse_entries(entries_body, expected_response_size):
    """Load serialized JSON response.

    Args:
        entries_body: received entries.
        expected_response_size: number of entries requested. Used to validate
            the response.

    Returns:
        a list of client_pb2.EntryResponse entries.

    Raises:
        InvalidResponseError: response not valid.
    """
    try:
        response = json.loads(entries_body)
    except ValueError as e:
        raise InvalidResponseError("Invalid response %s\n%s" %
                                   (entries_body, e))
    try:
        entries = iter(response["entries"])
    except (TypeError, KeyError) as e:
        raise InvalidResponseError("Invalid response: expected "
                                   "an array of entries, got %s\n%s)" %
                                   (response, e))
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
    response_size = len(response["entries"])
    if not response_size or response_size > expected_response_size:
        raise InvalidResponseError("Invalid response: requested %d entries,"
                                   "got %d entries" %
                                   (expected_response_size, response_size))
    return [_parse_entry(e) for e in entries]

def _parse_consistency_proof(response, servername):
    try:
        response = json.loads(response)
        consistency = [base64.b64decode(u) for u in response["consistency"]]
    except (TypeError, ValueError, KeyError) as e:
        raise InvalidResponseError(
              "%s returned invalid data: expected a base64-encoded "
              "consistency proof, got %s"
              "\n%s" % (servername, response, e))
    return consistency

# A class that we can mock out to generate fake responses.
class RequestHandler(object):
    """HTTPS requests."""
    def __init__(self, connection_timeout=60, ca_bundle=True, num_retries=None):
        self._timeout = connection_timeout
        self._ca_bundle = ca_bundle
        # Explicitly check for None as num_retries being 0 is valid.
        if num_retries is None:
            num_retries = FLAGS.get_entries_max_retries
        self._num_retries = num_retries

    def __repr__(self):
        return "%r()" % self.__class__.__name__

    def __str__(self):
        return "%r()" % self.__class__.__name__

    def get_response(self, uri, params=None):
        """Get an HTTP response for a GET request."""
        uri_with_params = self._uri_with_params(uri, params)
        num_get_attempts = self._num_retries + 1
        while num_get_attempts > 0:
            try:
                return requests.get(uri, params=params, timeout=self._timeout,
                                    verify=self._ca_bundle)
            except requests.exceptions.ConnectionError as e:
                # Re-tries regardless of the error.
                # Cannot distinguish between an incomplete read and other
                # transient (or permanent) errors when using requests.
                num_get_attempts = num_get_attempts - 1
                logging.info("Retrying fetching %s, error %s" % (
                        uri_with_params, e))
        raise HTTPError(
              "Connection to %s failed too many times." % uri_with_params)

    def post_response(self, uri, post_data):
        try:
            return requests.post(uri, data=json.dumps(post_data),
                                 timeout=self._timeout, verify=self._ca_bundle)
        except requests.exceptions.RequestException as e:
            raise HTTPError("POST to %s failed: %s" % (uri, e))

    @staticmethod
    def check_response_status(code, reason, content='', headers=''):
        if code == 200:
            return
        elif 400 <= code < 500:
            raise HTTPClientError("%s (%s) %s" % (reason, content, headers))
        elif 500 <= code < 600:
            raise HTTPServerError("%s (%s) %s" % (reason, content, headers))
        else:
            raise HTTPError("%s (%s) %s" % (reason, content, headers))

    @staticmethod
    def _uri_with_params(uri, params=None):
        if not params:
            return uri
        components = list(urlparse.urlparse(uri))
        if params:
            # Update the URI query, which is at index 4 of the tuple.
            components[4] = urllib.urlencode(params)
        return urlparse.urlunparse(components)

    def get_response_body(self, uri, params=None):
        response = self.get_response(uri, params=params)
        self.check_response_status(response.status_code, response.reason,
                                   response.content, response.headers)
        return response.content

    def post_response_body(self, uri, post_data=None):
        response = self.post_response(uri, post_data=post_data)
        self.check_response_status(response.status_code, response.reason,
                                   response.content, response.headers)
        return response.content


###############################################################################
#                         The synchronous log client.                         #
###############################################################################


class LogClient(object):
    """HTTP client for talking to a CT log."""

    """Create a new log client.

    Args:
        uri: The CT Log URI to communicate with.
        handler: A custom RequestHandler to use. If not specified, a new one
        will be created.
        connection_timeout: Timeout (in seconds) for all GET and POST requests.
        ca_bundle: True or a file path containing a set of CA roots. See
        Requests documentation for more information:
        http://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification
        Note that a false-y value is not allowed.
    """
    def __init__(self, uri, handler=None, connection_timeout=60,
                 ca_bundle=True):
        self._uri = uri
        if not ca_bundle:
          raise ClientError("Refusing to turn off SSL certificate checking.")
        if handler:
          self._request_handler = handler
        else:
          self._request_handler = RequestHandler(connection_timeout, ca_bundle)

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self._request_handler)

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, self._request_handler.uri)

    @property
    def servername(self):
        return self._uri

    def _req_body(self, path, params=None):
        return self._request_handler.get_response_body(self._uri + "/" + path,
                                                       params=params)

    def _post_req_body(self, path, post_data=None):
        return self._request_handler.post_response_body(
            self._uri + "/" + path, post_data=post_data)

    def _parse_sct(self, sct_response):
        sct_data = json.loads(sct_response)
        try:
            sct = client_pb2.SignedCertificateTimestamp()
            sct_version = sct_data["sct_version"]
            if sct_version != 0:
                raise InvalidResponseError(
                    "Unknown SCT version: %d" % sct_version)
            sct.version = client_pb2.V1
            sct.id.key_id = base64.b64decode(sct_data["id"])
            sct.timestamp = sct_data["timestamp"]
            hash_algorithm, sig_algorithm, sig_data = verify.decode_signature(
                base64.b64decode(sct_data["signature"]))
            sct.signature.hash_algorithm = hash_algorithm
            sct.signature.sig_algorithm = sig_algorithm
            sct.signature.signature = sig_data
            return sct
        except KeyError as e:
            raise InvalidResponseError("SCT Missing field: %s" % e)

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
            entries = _parse_entries(response, last - first + 1)
            for entry in entries:
                yield entry
            # If we got less entries than requested, then we don't know whether
            # the log imposed a batch limit or ran out of entries, so we keep
            # trying until we get all entries, or an error response.
            start += len(entries)

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

        return _parse_consistency_proof(response, self.servername)

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
            entry_response.entry.CopyFrom(_parse_entry(response))
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

    def add_chain(self, certs_list):
        """Adds the given chain of certificates.

        Args:
            certs_list: A list of DER-encoded certificates to add.

        Returns:
            The SCT for the certificate.

        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed.
                For logs that honour HTTP status codes, HTTPClientError (a 4xx)
                should never happen.
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        sct_data = self._post_req_body(
            _ADD_CHAIN,
            {'chain': [base64.b64encode(certificate) for certificate in certs_list]})
        return self._parse_sct(sct_data)
