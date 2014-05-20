import gflags
import logging
import threading
import time

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("probe_frequency_secs", 10*60,
                      "How often to probe the logs for updates")

from ct.client import log_client
from ct.client import monitor
from ct.client import state
from ct.crypto import merkle
from ct.crypto import verify

class ProberThread(threading.Thread):
    """A prober for scheduled updating of the log view."""
    def __init__(self, ct_logs, db, temp_db_factory, monitor_state_dir):
        """Initialize from a CtLogs proto."""
        threading.Thread.__init__(self)

        self.__monitors = []
        self.__db = db
        for log in ct_logs.ctlog:
            if not log.log_server or not log.log_id or not log.public_key_info:
                raise RuntimeError("Cannot start monitor: log proto has "
                                   "missing or empty fields: %s" % log)
            client = log_client.LogClient(log.log_server)
            hasher = merkle.TreeHasher()
            verifier = verify.LogVerifier(log.public_key_info,
                                          merkle.MerkleVerifier(hasher))
            state_keeper = state.StateKeeper(FLAGS.monitor_state_dir +
                                             "/" + log.log_id)
            temp_db = temp_db_factory.create_storage(log.log_server)
            self.__monitors.append(monitor.Monitor(client, verifier, hasher, db,
                                                   temp_db, state_keeper))

        self.__last_update_start_time = 0
        self.__stopped = False

    def __repr__(self):
        ret = "%r(%r)" % (self.__class__.__name__, self.__monitors)
    def __str__(self):
       return "%s(%s)" % (self.__class__.__name__, self.__monitors)

    def probe_all_logs(self):
        logging.info("Starting probe loop")
        start_time = time.time()
        """Loop through all logs in the list and check for updates."""
        for monitor in self.__monitors:
            if monitor.update():
                logging.info("Data for %s updated: latest timestamp is %s" %
                             (monitor.servername,
                              time.strftime("%c", time.localtime(
                                monitor.data_timestamp/1000))))
            else:
                logging.error("Failed to update data for %s: latest timestamp "
                              "is %s" % (monitor.servername,
                                         time.strftime("%c", time.localtime(
                                monitor.data_timestamp/1000))))
        logging.info("Probe loop completed in %d seconds" %
                     (time.time() - start_time))

    def run(self):
        while not self.__stopped:
            sleep_time = max(0, self.__last_update_start_time +
                             FLAGS.probe_frequency_secs - time.time())
            time.sleep(sleep_time)
            self.__last_update_start_time = time.time()
            self.probe_all_logs()

    def stop(self):
        self.__stopped = True
