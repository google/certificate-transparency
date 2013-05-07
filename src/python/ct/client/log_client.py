import gflags
import json
import logging
import requests
import threading
import time

from ct.proto.client_pb2 import SthResponse

FLAGS = gflags.FLAGS

gflags.DEFINE_integer('probe_frequency_secs', 10*60,
                      "How often to probe the logs for updates")

class LogClient(object):
    """HTTP client for talking to a CT log."""

    get_sth_path = "ct/v1/get-sth"

    def __init__(self, uri):
        self.uri = uri

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self.uri)

    def __str__(self):
        return "%s(%s)" % (self.__class__.__name__, self.uri)

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
        sth_response = SthResponse()
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

class LogProber(threading.Thread):
    """A prober for scheduled updating of the log view."""
    def __init__(self, ct_server_list, db):
        self.stopped = False
        threading.Thread.__init__(self)

        self.clients = []
        self.db = db
        for log in ct_server_list:
            self.clients.append(LogClient(log))

        self.last_update_start_time = 0

    def __repr__(self):
        return "%r(%r)" % (self.__class__.__name__, self.clients)

    def __str__(self):
        ret = "%s: " % self.__class__.__name__
        ret.append(' '.join([str(c) for c in self.clients]))
        return ret

    def probe_all_logs(self):
        for client in self.clients:
            sth_response = client.get_sth()
            if sth_response:
                self.db.store_sth(client.servername(), sth_response)

    def run(self):
        while not self.stopped:
            sleep_time = (self.last_update_start_time +
                          FLAGS.probe_frequency_secs - time.time())
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.last_update_start_time = time.time()
            self.probe_all_logs()
