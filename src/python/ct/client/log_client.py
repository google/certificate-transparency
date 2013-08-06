import base64
import gflags
import logging
import requests
import threading
import time

from ct.crypto import error, verify
from ct.proto import client_pb2

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("probe_frequency_secs", 10*60,
                      "How often to probe the logs for updates")
gflags.DEFINE_integer("entry_batch_size", 1000, "Maximum number of entries to "
                      "attempt to fetch in one request")

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

# requests.models.Response is not easily instantiable locally, so as a
# workaround, encapsulate the entire http logic in the Requester class which we
# can control/mock out to test response handling.
class Requester(object):
    def __init__(self, uri):
        self.__uri = uri

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self.__uri)

    def __str__(self):
        return "%r(%r)" % (self.__class__.__name__, self.__uri)

    @property
    def uri(self):
        return self.__uri

    def get_json_response(self, path, params={}):
        """Get the json contents of a request response."""
        url = "https://" + self.__uri + "/" + path
        try:
            response = requests.get(url, params=params, timeout=60)
        except requests.exceptions.RequestException as e:
            raise HTTPError("Connection to %s failed: %s" % (url, e))
        if not response.ok:
            error_msg = ("%s returned http_error %d: %s" %
                         (url, response.status_code, response.text))
            if 400 <= response.status_code  < 500:
                raise HTTPClientError(error_msg)
            elif 500 <= response.status_code < 600:
                raise HTTPServerError(error_msg)
            else:
                raise HTTPError(error_msg)
        try:
            return response.json()
        # This can raise a variety of undocumented exceptions...
        except e:
            raise InvalidResponseError("Response %s from %s is not valid JSON: "
                                       "%s" % (response, url, e))

class LogClient(object):
    """HTTP client for talking to a CT log."""

    _GET_STH_PATH = "ct/v1/get-sth"
    _GET_ENTRIES_PATH = "ct/v1/get-entries"

    def __init__(self, requester):
        self.__req = requester

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self.__req)

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, self.__req.uri)

    @property
    def servername(self):
        return self.__req.uri

    def get_sth(self):
        """Get the current Signed Tree Head.
        Returns: a ct.proto.client_pb2.SthResponse proto
        Raises:
            HTTPError, HTTPClientError, HTTPServerError: connection failed.
                For logs that honour HTTP status codes, HTTPClientError (a 4xx)
                should never happen.
            InvalidResponseError: server response is invalid for the given
                                  request.
        """
        sth = self.__req.get_json_response(self._GET_STH_PATH)
        sth_response = client_pb2.SthResponse()
        try:
            sth_response.timestamp = sth["timestamp"]
            sth_response.tree_size = sth["tree_size"]
            sth_response.sha256_root_hash = base64.b64decode(sth[
                "sha256_root_hash"])
            sth_response.tree_head_signature = base64.b64decode(sth[
                "tree_head_signature"])
        # TypeError for base64 decoding, TypeError/ValueError for invalid
        # JSON field types, KeyError for missing JSON fields.
        except (TypeError, ValueError, KeyError) as e:
            raise InvalidResponseError("%s returned an invalid STH %s\n%s" %
                                       (self.__req.uri, sth, e))
        return sth_response

    def __json_entry_to_response(self, json_entry):
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
                "\n%s" % (self.__req.uri, json_entry, e))
        return entry_response

    def __validated_entry_response(self, start, end, response):
        """Verify the get-entries response format and size. Returns an array
        of entries."""
        entries = None
        try:
            entries = iter(response["entries"])
        except (TypeError, KeyError) as e:
            raise InvalidResponseError("%s returned invalid data: expected "
                                       "an array of entries, got %s\n%s)" %
                                       (self.__req.uri, response, e))
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
                "entries" % (self.__req.uri, expected_response_size,
                             response_size))

        # If any one of the entries has invalid json format, this raises.
        return map(lambda e: self.__json_entry_to_response(e), entries)

    def get_entries(self, start, end, batch_size=FLAGS.entry_batch_size):
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

        while start <= end:
            # Note that an HTTPError may occur here if the log does not have the
            # requested range of entries available. RFC 6962 says:
            # "Any errors will be returned as HTTP 4xx or 5xx responses, with
            # human-readable error messages."
            # There is thus no easy way to distinguish this case from other
            # errors.
            first = start
            last = min(start + batch_size - 1, end)
            response = self.__req.get_json_response(
                self._GET_ENTRIES_PATH, params={"start": first, "end": last})
            valid_entries = self.__validated_entry_response(first, last,
                                                            response)
            for entry in valid_entries:
                yield entry
            # If we got less entries than requested, then we don't know whether
            # the log imposed a batch limit or ran out of entries, so we keep
            # trying until we get all entries, or an error response.
            start += len(valid_entries)

# TODO(ekasper): move to another module.
class LogProber(object):
    def __init__(self, ctlog):
        """Initialize from a CtLogMetadata proto."""
        if ctlog.log_server is None:
            raise ClientError("Cannot initialize log client: "
                              "no server URI given.")
        self.client = LogClient(Requester(ctlog.log_server))
        self.verifier = None
        if ctlog.public_key_info is not None:
            self.verifier = verify.LogVerifier(ctlog.public_key_info)
        else:
            logging.warning("No public key info given for log server %s, "
                            "proceeding without verification" % log.log_server)

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self.clients)

    def __str__(self):
        ret = "%s: " % self.__class__.__name__
        ret.append(" ".join([str(c) for c in self.clients]))
        return ret

    @property
    def servername(self):
        return self.client.servername

    def probe_sth(self):
        try:
            sth_response = self.client.get_sth()
        except (HTTPError, InvalidResponseError) as e:
           # TODO(ekasper): export stats about probe failures.
           logging.error("Probing %s failed: %s" % (self.servername, e))
           return

        audited_sth = client_pb2.AuditedSth()
        audited_sth.sth.CopyFrom(sth_response)
        audited_sth.audit.status = client_pb2.UNVERIFIED
        if self.verifier is None:
            return sth_response

        try:
            self.verifier.verify_sth(sth_response)
            logging.debug("STH verified")
        except error.VerifyError:
            # TODO(ekasper): export stats about probe failures.
            logging.error("Invalid STH signature for %s" %
                          self.servername)
            audited_sth.audit.status = client_pb2.VERIFY_ERROR
        else:
            audited_sth.audit.status = client_pb2.VERIFIED
        return audited_sth

class ProberThread(threading.Thread):
    """A prober for scheduled updating of the log view."""
    def __init__(self, ct_logs, db):
        """Initialize from a CtLogs proto."""
        self.stopped = False
        threading.Thread.__init__(self)

        self.probers = []
        self.db = db
        for log in ct_logs.ctlog:
            self.probers.append(LogProber(log))

        self.last_update_start_time = 0

    def __repr__(self):
        return "%r(%r, %r)" % (self.__class__.__name__, self.client,
                               self.verifier)

    def __str__(self):
       return "%s(%s, %s)" % (self.__class__.__name__, self.client,
                              self.verifier)

    def probe_all_logs(self):
        for prober in self.probers:
            audited_sth = prober.probe_sth()
            if audited_sth:
                # TODO(ekasper): make it configurable whether to store
                # unverified data.
                self.db.store_sth(prober.servername, audited_sth)
            else:
                logging.error("No valid response from %s" % prober.servername)

    def run(self):
        while not self.stopped:
            sleep_time = (self.last_update_start_time +
                          FLAGS.probe_frequency_secs - time.time())
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.last_update_start_time = time.time()
            self.probe_all_logs()
