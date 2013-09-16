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
gflags.DEFINE_bool("verify_sth_consistency", False, "Verify consistency of STH "
                   "hashes. This is a temporary flag to keep things working "
                   "during development; it will eventually be removed and "
                   "effectively be always True thereafter.")

class Monitor(object):
    def __init__(self, client, verifier, db, temp_db, state_keeper):
        self.__client = client
        self.__verifier = verifier
        self.__db = db
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

    def _get_verified_batch_sth(self):
        """Get the verified STH or partial STH of the previous batch."""
        old_state = self.__state
        if old_state.verified_partial_sth.tree_size:
            return old_state.verified_partial_sth
        else:
            return old_state.verified_sth

    def _set_pending_batch_sth(self, new_sth):
        """Set the pending STH if new tree is bigger, else the verified STH."""
        if new_sth.tree_size < self.__state.verified_sth.tree_size:
            raise ValueError("pending size must be >= verified size")
        if new_sth.timestamp <= self.__state.verified_sth.timestamp:
            raise ValueError("pending time must be > verified time")
        new_state = client_pb2.MonitorState()
        new_state.CopyFrom(self.__state)
        if new_sth.tree_size > self.__state.verified_sth.tree_size:
            new_state.pending_sth.CopyFrom(new_sth)
        else:
            new_state.verified_sth.CopyFrom(new_sth)
        self.__update_state(new_state)

    def _set_verified_batch_sth(self, batch_pending_sth):
        """Set the verified STH or partial STH to the current batch."""
        old_state = self.__state
        new_state = client_pb2.MonitorState()
        new_state.CopyFrom(self.__state)
        if old_state.pending_sth.tree_size == batch_pending_sth.tree_size:
            # all pending entries retrieved
            # already did consistency checks so this should always be true
            #assert (old_state.pending_sth.sha256_root_hash ==
            #        batch_pending_sth.sha256_root_hash)
            new_state.verified_sth.CopyFrom(old_state.pending_sth)
            new_state.ClearField("pending_sth")
            new_state.ClearField("verified_partial_sth")
        else:
            new_state.verified_partial_sth.CopyFrom(batch_pending_sth)
        self.__update_state(new_state)

    def _verify_consistency(self, old_sth, new_sth):
        try:
            if not FLAGS.verify_sth_consistency:
                return self.__verifier.verify_sth_temporal_consistency(
                    old_sth, new_sth)

            proof = self.__client.get_sth_consistency(
                old_sth.tree_size, new_sth.tree_size)
            logging.debug("got proof for (%s, %s): %s",
                old_sth.tree_size, new_sth.tree_size,
                map(lambda b: b[:8].encode("base64")[:-2] + "...", proof))
            self.__verifier.verify_sth_consistency(old_sth, new_sth, proof)
        except error.VerifyError as e:
            # catches both ConsistencyError and ProofError. when alerts are
            # implemented, only the former should trigger an immediate alert;
            # the latter may have innocent causes (e.g. data corruption,
            # software bug) so we could give it a chance to recover before
            # alerting.
            logging.error("Could not verify STH consistency: %s vs %s!!!\n%s" %
                          (old_sth, new_sth, e))
            raise

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

        # If we got the same response as last time, do nothing.
        # If we got an older response than last time, return False.
        # (It is not necessarily an inconsistency - the log could be out of
        # sync - but we should not rewind to older data.)
        #
        # The client should always return an STH but best eliminate the
        # None == None case explicitly by only shortcutting the verification
        # if we already have a verified STH.
        if self.__state.HasField("verified_sth"):
                if sth_response == self.__state.verified_sth:
                    logging.info("Ignoring already-verified STH: %s" %
                                 sth_response)
                    return True
                elif (sth_response.timestamp <
                      self.__state.verified_sth.timestamp):
                    logging.error("Rejecting received STH: timestamp is older "
                                  "than current verified STH: %s vs %s " %
                                  (sth_response, self.__state.verified_sth))
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

        # Verify consistency to catch the log trying to trick us
        # into rewinding the tree.
        try:
            self._verify_consistency(self.__state.verified_sth, sth_response)
        except error.VerifyError:
            return False

        # We now have a valid STH that is newer than our current STH: we should
        # be holding on to it until we have downloaded and verified data under
        # its signature.
        logging.info("STH verified, updating state.")
        self._set_pending_batch_sth(sth_response)
        return True

    @staticmethod
    def __estimate_time(num_new_entries):
        if num_new_entries < 1000:
            return "a moment"
        elif num_new_entries < 1000000:
            return "a while"
        else:
            return "all night"

    def __fetch_entries(self, start, end):
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
                return False
            if not entry_batch:
                # Generator exhausted prematurey.
                logging.error("Failed to fetch all entries: expected tree size "
                              "%d vs retrieved tree size %d" %
                              (end + 1, next_sequence_number))
                return False
            numbered_batch = zip(range(next_sequence_number,
                                       next_sequence_number +
                                       len(entry_batch)),
                                 entry_batch)
            logging.info("Fetched %d entries" % len(entry_batch))

            last_verified_sth = self._get_verified_batch_sth()
            # check that the batch is consistent with the eventual pending_sth
            try:
                # calculate the theoretical STH for the latest fetched cert
                batch_pending_sth = client_pb2.SthResponse()
                batch_pending_sth.tree_size = numbered_batch[-1][0] + 1
                # we only want to check the hash, so just use a dummy timestamp
                # that looks valid so the verifier doesn't complain
                batch_pending_sth.timestamp = 0
                # TODO(ekasper): Compute updated Merkle root hash
                batch_pending_sth.sha256_root_hash = "NotImplemented"
                self._verify_consistency(
                    batch_pending_sth, self.__state.pending_sth)
            except error.VerifyError:
                return False
            logging.info("Verified %d entries" % len(entry_batch))

            self._set_verified_batch_sth(batch_pending_sth)
            # TODO(ekasper): parse temporary data into permanent storage.

            next_sequence_number += len(entry_batch)

        return True

    def _update_entries(self):
        """Retrieve new entries according to the pending STH.
        Returns: True if the update succeeded.
        """
        if not self.__state.HasField("pending_sth"):
            return True
        # Default is 0, which is what we want.
        wanted_entries = self.__state.pending_sth.tree_size
        last_verified_size = self._get_verified_batch_sth().tree_size

        if (wanted_entries > last_verified_size and not
            self.__fetch_entries(last_verified_size, wanted_entries-1)):
            return False
        return True

    def update(self):
        """Update log view. Returns True if the update succeeded, False if any
        error occurred."""
        logging.info("Starting update for %s" % self.servername)
        if not self._update_sth() or not self._update_entries():
            logging.error("Update failed")
            return False

        return True
