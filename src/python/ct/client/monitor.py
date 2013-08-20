import itertools
import gflags
import logging
import os

from ct.client import log_client
from ct.client import state
from ct.client import temp_db
from ct.crypto import error
from ct.proto import client_pb2

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("entry_write_batch_size", 1000, "Maximum number of "
                      "entries to batch into one database write")

class Monitor(object):
    def __init__(self, client, verifier, db, temp_db, state_keeper):
        self.__client = client
        self.__verifier = verifier
        self.__db = db
        self.__unverified_db = temp_db
        self.__state_keeper = state_keeper

        # TODO(ekasper): once consistency checks are in place, also load/store
        # Merkle tree info.
        # Depends on: Merkle trees implemented in Python.
        self.__state = client_pb2.MonitorState()
        try:
            self.__state = self.__state_keeper.read(client_pb2.MonitorState)
        except state.FileNotFoundError:
            # TODO(ekasper): initialize state file with a setup script, so we
            # can raise with certainty when it's not found.
            logging.warning("Monitor state file not found, assuming first "
                            "run.")
        else:
          if not self.__state.HasField("verified_sth"):
            logging.warning("No verified monitor state, assuming first run.")

    def __repr__(self):
        return "%r(%r, %r, %r, %r)" % (self.__class__.__name__, self.__client,
                                       self.__verifier, self.__db,
                                       self.__state_file)

    def __str__(self):
        return "%s(%s, %s, %s, %s)" % (self.__class__.__name__, self.__client,
                                       self.__verifier, self.__db,
                                       self.__state_file)

    def __update_state(self, new_state):
        """Update state and write to disk."""
        self.__state_keeper.write(new_state)
        self.__state = new_state
        logging.info("New state is %s" % new_state)

    @property
    def servername(self):
        return self.__client.servername

    @property
    def data_timestamp(self):
        """Timestamp of the latest verified data, in milliseconds since epoch.
        """
        return self.__state.verified_sth.timestamp

    def _update_sth(self):
        """Get a new candidate STH. If update succeeds, stores the new STH as
        pending. Does nothing if there is already a pending
        STH.
        Returns: True if the update succeeded."""
        if self.__state.HasField("pending_sth"):
            return True
        logging.info("Fetching new STH")
        try:
            sth_response = self.__client.get_sth()
            logging.info("Got new STH: %s" % sth_response)
        except (log_client.HTTPError, log_client.InvalidResponseError) as e:
            logging.error("get-sth from %s failed: %s" % (self.servername, e))
            return False

        try:
            # Given that we now only store verified STHs, the audit info here
            # is not all that useful.
            # TODO(ekasper): we should be tracking consistency instead.
            self.__verifier.verify_sth(sth_response)
            audited_sth = client_pb2.AuditedSth()
            audited_sth.sth.CopyFrom(sth_response)
            audited_sth.audit.status = client_pb2.VERIFIED
            self.__db.store_sth(self.servername, audited_sth)
        except (error.EncodingError, error.VerifyError) as e:
            logging.error("Invalid STH: %s" % sth_response)
            return False

        # If we have no verified STH, this will also work with 0-defaults
        # returned by protocol buffers.
        if sth_response.timestamp < self.__state.verified_sth.timestamp:
            logging.error("Rejecting received STH: timestamp is older than "
                          "current verified STH: %s vs %s " %
                          (sth_response, self.__state.verified_sth))
            return False
        # Verify temporal consistency to catch the log trying to trick us
        # into rewinding the tree.
        try:
            self.__verifier.verify_sth_temporal_consistency(
                self.__state.verified_sth, sth_response)
        except error.ConsistencyError as e:
            # TODO(ekasper): fire an alert.
            logging.error("Inconsistent STHs: %s vs %s!!!\n%s" %
                          (sth_response, self.__state.verified_sth, e))
            return False

        # We now have a valid STH that is newer than our current STH: we should
        # be holding on to it until we have downloaded and verified data under
        # its signature.
        logging.info("STH verified, updating state.")
        new_state = client_pb2.MonitorState()
        new_state.CopyFrom(self.__state)
        new_state.pending_sth.CopyFrom(sth_response)
        self.__update_state(new_state)
        return True

    @staticmethod
    def __estimate_time(num_new_entries):
        if num_new_entries < 1000:
            return "a moment"
        elif num_new_entries < 1000000:
            return "a while"
        else:
            return "all night"

    def __fetch_unverified_entries(self, start, end):
        num_new_entries = end - start + 1
        logging.info("Fetching %d new entries: this will take %s..." %
                     (num_new_entries,
                      self.__estimate_time(num_new_entries)))
        new_entries = self.__client.get_entries(start, end)
        next_sequence_number = start

        # Loop until we a) have all entries b) error out or c) exhaust the
        # generator.
        while next_sequence_number < end + 1:
            try:
                entry_batch = list(itertools.islice(
                        new_entries, FLAGS.entry_write_batch_size))
            except (log_client.HTTPError,
                    log_client.InvalidResponseError) as e:
                logging.error("get-entries from %s failed: %s" %
                              (self.servername, e))
                self.__unverified_db.drop_entries()
                return False
            if not entry_batch:
                # Generator exhausted prematurey.
                logging.error("Failed to fetch all entries: expected tree size "
                              "%d vs retrieved tree size %d" %
                              (end + 1, next_sequence_number))
                self.__unverified_db.drop_entries()
                return False
            numbered_batch = zip(range(next_sequence_number,
                                       next_sequence_number +
                                       len(entry_batch)),
                                 entry_batch)

            logging.info("Fetched %d entries" % len(entry_batch))
            self.__unverified_db.store_entries(numbered_batch)
            next_sequence_number += len(entry_batch)

        return True

    def _update_entries(self):
        """Retrieve new entries according to the pending STH.
        Returns: True if the update succeeded.
        """
        assert self.__state.HasField("pending_sth")
        # If we have old data, drop it.
        # TODO(ekasper): optimize this by keeping partially fetched entries
        # in case a large download fails half-way through.
        self.__unverified_db.drop_entries()

        # Default is 0, which is what we want.
        num_entries = self.__state.verified_sth.tree_size

        if (self.__state.pending_sth.tree_size > num_entries and
            not self.__fetch_unverified_entries(
                num_entries, self.__state.pending_sth.tree_size-1)):
            return False

        # TODO(ekasper): Compute updated Merkle root hash (this can be done
        # on the fly while fetching entries) and check that the new root hash
        # matches the hash in the STH. Note that if there were no new entries,
        # this check is the same as checking that the root hash didn't change.
        #
        # For now we just pretend we have done a consistency check.
        new_state = client_pb2.MonitorState()
        new_state.verified_sth.CopyFrom(self.__state.pending_sth)
        self.__update_state(new_state)
        return True

    def update(self):
        """Update log view. Returns True if the update succeeded, False if any
        error occurred."""
        logging.info("Starting update for %s" % self.servername)
        if not self._update_sth() or not self._update_entries():
            logging.error("Update failed")
            return False

        # TODO(ekasper): parse temporary data into permanent storage.
        return True
