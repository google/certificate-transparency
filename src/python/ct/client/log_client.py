import gflags
import json
import logging
import requests
import threading
import time

from ct.crypto import verify
from ct.proto import client_pb2

FLAGS = gflags.FLAGS

gflags.DEFINE_integer('probe_frequency_secs', 10*60,
                      "How often to probe the logs for updates")

class Error(Exception):
    pass

class ClientError(Error):
    pass

class LogClient(object):
    """HTTP client for talking to a CT log."""

    get_sth_path = "ct/v1/get-sth"

    def __init__(self, uri):
        self.uri = uri

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self.uri)

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, self.uri)

    @property
    def servername(self):
        return self.uri

    def _get_request(self, path, params={}):
        """GET <logserver>/path?params."""
        url = "https://" + self.uri + "/" + path
        try:
            response = requests.get(url, params=params, timeout=60)
        except requests.exceptions.RequestException as e:
            logging.error("Connection to %s failed: %s", url, e)
            return

        if response.status_code == 200:
            return response.json()
        else:
            # TODO(ekasper): handle JSON error responses.
            logging.error("%s returned http error %d: %s", url,
                          response.status_code, response.text)

    def get_sth(self):
        """Get the current Signed Tree Head."""
        sth = self._get_request(LogClient.get_sth_path)
        if not sth:
            return
        sth_response = client_pb2.SthResponse()
        try:
            sth_response.timestamp = sth['timestamp']
            sth_response.tree_size = sth['tree_size']
            sth_response.sha256_root_hash = sth[
                'sha256_root_hash'].decode("base64")
            sth_response.tree_head_signature = sth[
                'tree_head_signature'].decode("base64")
        except:
            logging.error("%s returned invalid JSON: %s", self.uri, sth)
            return

        return sth_response

class LogProber(object):
    def __init__(self, ctlog):
        """Initialize from a CtLogMetadata proto."""
        if ctlog.log_server is None:
            raise ClientError("Cannot initialize log client: "
                              "no server URI given.")
        self.client = LogClient(ctlog.log_server)
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
        ret.append(' '.join([str(c) for c in self.clients]))
        return ret

    @property
    def servername(self):
        return self.client.servername

    def probe_sth(self):
        sth_response = self.client.get_sth()
        if sth_response is None:
            return None
        audited_sth = client_pb2.AuditedSth()
        audited_sth.sth.CopyFrom(sth_response)
        if self.verifier is None:
            audited_sth.audit.status = client_pb2.UNVERIFIED
            return sth_response
        if self.verifier.verify_sth(sth_response):
            logging.debug("STH verified")
            audited_sth.audit.status = client_pb2.VERIFIED
        else:
            # TODO(ekasper): export stats about probe failures.
            logging.error("Invalid STH signature for %s" %
                          self.servername)
            audited_sth.audit.status = client_pb2.VERIFY_ERROR
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
                logging.error("No valid response from %s", prober.servername)

    def run(self):
        while not self.stopped:
            sleep_time = (self.last_update_start_time +
                          FLAGS.probe_frequency_secs - time.time())
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.last_update_start_time = time.time()
            self.probe_all_logs()
