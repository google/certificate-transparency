"""RFC 6962 client API."""

from ct.client import log_client
from ct.client.db import database
import gflags
import logging
import random

from twisted.internet import defer
from twisted.internet import error
from twisted.internet import protocol
from twisted.internet import reactor as ireactor
from twisted.internet import task
from twisted.internet import threads
from twisted.python import failure
from twisted.web import client
from twisted.web import http
from twisted.web import iweb
from Queue import Queue
from zope.interface import implements


FLAGS = gflags.FLAGS

gflags.DEFINE_integer("max_fetchers_in_parallel", 100, "Maximum number of "
                      "concurrent fetches.")

gflags.DEFINE_integer("get_entries_retry_delay", 1, "Number of seconds after "
                      "which get-entries will be retried if it encountered "
                      "an error.")

gflags.DEFINE_integer("entries_buffer", 100000, "Size of buffer which stores "
                      "fetched entries before async log client is able to "
                      "return them. 100000 entries shouldn't take more "
                      "than 600 Mb of memory.")

gflags.DEFINE_integer("response_buffer_size_bytes", 50 * 1000 * 1000, "Maximum "
                      "size of a single response buffer. Should be set such "
                      "that a get_entries response comfortably fits in the "
                      "the buffer. A typical log entry is expected to be < "
                      "10kB.")

gflags.DEFINE_bool("persist_entries", True, "Cache entries on disk.")

class HTTPConnectionError(log_client.HTTPError):
    """Connection failed."""
    pass


class HTTPResponseSizeExceededError(log_client.HTTPError):
    """HTTP response exceeded maximum permitted size."""
    pass


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


class AsyncRequestHandler(object):
    """A helper for asynchronous response body delivery."""

    def __init__(self, agent):
        self._agent = agent

    @staticmethod
    def _response_cb(response):
        try:
            log_client.RequestHandler.check_response_status(
                    response.code, response.phrase,
                    list(response.headers.getAllRawHeaders()))
        except log_client.HTTPError as e:
            return failure.Failure(e)
        finished = defer.Deferred()
        response.deliverBody(ResponseBodyHandler(finished))
        return finished

    @staticmethod
    def _make_request(path, params):
        if not params:
            return path
        return path + "?" + "&".join(["%s=%s" % (key, value)
                                      for key, value in params.iteritems()])

    def get(self, path, params=None):
        d = self._agent.request("GET", self._make_request(path, params))
        d.addCallback(self._response_cb)
        return d


class EntryProducer(object):
    """A push producer for log entries."""
    implements(iweb.IBodyProducer)

    def __init__(self, handler, reactor, uri, start, end,
                 batch_size, entries_db=None):
        self._handler = handler
        self._reactor = reactor
        self._uri = uri
        self._entries_db = entries_db
        self._consumer = None

        assert 0 <= start <= end
        self._start = start
        self._end = end
        self._current = self._start
        self._batch_size = batch_size
        self._batches = Queue()
        self._currently_fetching = 0
        self._currently_stored = 0
        self._last_fetching = self._current
        self._max_currently_fetching = (FLAGS.max_fetchers_in_parallel *
                                        self._batch_size)
        # Required attribute of the interface.
        self.length = iweb.UNKNOWN_LENGTH
        self.min_delay = FLAGS.get_entries_retry_delay

    @property
    def finished(self):
        return self._current > self._end

    def __fail(self, failure):
        if not self._stopped:
            self.stopProducing()
            self._done.errback(failure)

    @staticmethod
    def _calculate_retry_delay(retries):
        """Calculates delay based on number of retries which already happened.

        Random is there, so we won't attack server lots of requests exactly
        at the same time, and 1.3 is nice constant for exponential back-off."""
        return ((0.4 + random.uniform(0.3, 0.6)) * FLAGS.get_entries_retry_delay
                * 1.4**retries)

    def _response_eb(self, failure, first, last, retries):
        """Error back for HTTP errors"""
        if not self._paused:
            # if it's not last retry and failure wasn't our fault we retry
            if (retries < FLAGS.get_entries_max_retries and
                not failure.check(log_client.HTTPClientError)):
                logging.info("Retrying get-entries for range <%d, %d> retry: %d"
                             % (first, last, retries))
                d = task.deferLater(self._reactor,
                                  self._calculate_retry_delay(retries),
                                  self._fetch_parsed_entries,
                                  first, last)
                d.addErrback(self._response_eb, first, last, retries + 1)
                return d
            else:
                self.__fail(failure)

    def _fetch_eb(self, failure):
        """Error back for errors after getting result of a request
        (InvalidResponse)"""
        self.__fail(failure)

    def _write_pending(self):
        d = defer.Deferred()
        d.callback(None)
        if self._pending:
            self._current += len(self._pending)
            self._currently_stored -= len(self._pending)
            d = self._consumer.consume(self._pending)
            self._pending = None
        return d

    def _batch_completed(self, result):
        self._currently_fetching -= len(result)
        self._currently_stored += len(result)
        return result

    def _store_batch(self, entry_batch, start_index):
        assert self._entries_db
        d = threads.deferToThread(self._entries_db.store_entries,
                                  enumerate(entry_batch, start_index))
        d.addCallback(lambda _: entry_batch)
        return d

    def _get_entries_from_db(self, first, last):
        if FLAGS.persist_entries and self._entries_db:
            d = threads.deferToThread(self._entries_db.scan_entries, first, last)
            d.addCallbacks(lambda entries: list(entries))
            d.addErrback(lambda fail: fail.trap(database.KeyError) and None)
            return d
        else:
            d = defer.Deferred()
            d.callback(None)
            return d

    def _fetch_parsed_entries(self, first, last):
        # first check in database
        d = self._get_entries_from_db(first, last)
        d.addCallback(self._sub_fetch_parsed_entries, first, last)
        return d

    def _sub_fetch_parsed_entries(self, entries, first, last):
        # it's not the best idea to attack server with many requests exactly at
        # the same time, so requests are sent after slight delay.
        if not entries:
            request = task.deferLater(self._reactor,
                                      self._calculate_retry_delay(0),
                                      self._handler.get,
                                      self._uri + "/" +
                                      log_client._GET_ENTRIES_PATH,
                                      params={"start": str(first),
                                              "end": str(last)})
            request.addCallback(log_client._parse_entries, last - first + 1)
            if self._entries_db and FLAGS.persist_entries:
                request.addCallback(self._store_batch, first)
            entries = request
        else:
            deferred_entries = defer.Deferred()
            deferred_entries.callback(entries)
            entries = deferred_entries
        return entries

    def _create_next_request(self, first, last, entries, retries):
        d = self._fetch_parsed_entries(first, last)
        d.addErrback(self._response_eb, first, last, retries)
        d.addCallback(lambda result: (entries + result, len(result)))
        d.addCallback(self._fetch, first, last, retries)
        return d

    def _fetch(self, result, first, last, retries):
        entries, last_fetched_entries_count = result
        next_range_start = first + last_fetched_entries_count
        if next_range_start > last:
            return entries
        return self._create_next_request(next_range_start, last,
                                         entries, retries)

    def _create_fetch_deferred(self, first, last, retries=0):
        d = defer.Deferred()
        d.addCallback(self._fetch, first, last, retries)
        d.addCallback(self._batch_completed)
        d.addErrback(self._fetch_eb)
        d.callback(([], 0))
        return d

    @defer.deferredGenerator
    def produce(self):
        """Produce entries."""
        while not self._paused:
            wfd = defer.waitForDeferred(self._write_pending())
            yield wfd
            wfd.getResult()

            if self.finished:
                self.finishProducing()
                return
            first = self._last_fetching
            while (self._currently_fetching <= self._max_currently_fetching and
                   self._last_fetching <= self._end and
                   self._currently_stored <= FLAGS.entries_buffer):
                last = min(self._last_fetching + self._batch_size - 1, self._end,
                   self._last_fetching + self._max_currently_fetching
                           - self._currently_fetching + 1)
                self._batches.put(self._create_fetch_deferred(first, last))
                self._currently_fetching += last - first + 1
                first = last + 1
                self._last_fetching = first

            wfd = defer.waitForDeferred(self._batches.get())
            # Pause here until the body of the response is available.
            yield wfd
            # The producer may have been paused while waiting for the response,
            # or errored out upon receiving it: do not write the entries out
            # until after the next self._paused check.
            self._pending = wfd.getResult()

    def startProducing(self, consumer):
        """Start producing entries.

        The producer writes EntryResponse protos to the consumer in batches,
        until all entries have been received, or an error occurs.

        Args:
            consumer: the consumer to write to.

        Returns:
           a deferred that fires when no more entries will be written.
           Upon success, this deferred fires number of produced entries or
           None if production wasn't successful. Upon failure, this deferred
           fires with the appropriate HTTPError.

        Raises:
            RuntimeError: consumer already registered.
        """
        if self._consumer:
            raise RuntimeError("Producer already has a consumer registered")
        self._consumer = consumer
        self._stopped = False
        self._paused = True
        self._pending = None
        self._done = defer.Deferred()
        # An IBodyProducer should start producing immediately, without waiting
        # for an explicit resumeProducing() call.
        task.deferLater(self._reactor, 0, self.resumeProducing)
        return self._done

    def pauseProducing(self):
        self._paused = True

    def resumeProducing(self):
        if self._paused and not self._stopped:
            self._paused = False
            d = self.produce()
            d.addErrback(self.finishProducing)

    def stopProducing(self):
        self._paused = True
        self._stopped = True

    def finishProducing(self, failure=None):
        self.stopProducing()
        if not failure:
            self._done.callback(self._end - self._start + 1)
        else:
            self._done.errback(failure)


class AsyncLogClient(object):
    """A twisted log client."""

    def __init__(self, agent, uri, entries_db=None, reactor=ireactor):

        """Initialize the client.

        If entries_db is specified and flag persist_entries is true, get_entries
        will return stored entries.

        Args:
            agent: the agent to use.
            uri: the uri of the log.
            entries_db: object that conforms TempDB API
            reactor: the reactor to use. Default is twisted.internet.reactor.
        """
        self._handler = AsyncRequestHandler(agent)
        #twisted expects bytes, so if uri is unicode we have to change encoding
        self._uri = uri.encode('ascii')
        self._reactor = reactor
        self._entries_db = entries_db

    @property
    def servername(self):
        return self._uri

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
        deferred_result = self._handler.get(self._uri + "/" +
                                            log_client._GET_STH_PATH)
        deferred_result.addCallback(log_client._parse_sth)
        return deferred_result

    def get_entries(self, start, end, batch_size=0):
        """Retrieve log entries.

        Args:
            start: index of first entry to retrieve.
            end: index of last entry to retrieve.
            batch_size: max number of entries to fetch in one go.

        Returns:
            an EntryProducer for the given range.

        Raises:
            InvalidRequestError: invalid request range (irrespective of log).

        Caller is responsible for ensuring that (start, end) is a valid range
        (by retrieving an STH first), otherwise a HTTPClientError may occur
        during production.
        """
        # Catch obvious mistakes here.
        if start < 0 or end < 0 or start > end:
            raise log_client.InvalidRequestError(
                    "Invalid range [%d, %d]" % (start, end))
        batch_size = batch_size or FLAGS.entry_fetch_batch_size
        return EntryProducer(self._handler, self._reactor, self._uri,
                             start, end, batch_size, self._entries_db)

    def get_sth_consistency(self, old_size, new_size):
        """Retrieve a consistency proof.

        Args:
            old_size  : size of older tree.
            new_size  : size of newer tree.

        Returns:
            a Deferred that fires with list of raw hashes (bytes) forming the
            consistency proof

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
            raise log_client.InvalidRequestError(
                "old > new: %s >= %s" % (old_size, new_size))

        if old_size < 0 or new_size < 0:
            raise log_client.InvalidRequestError(
                "both sizes must be >= 0: %s, %s" % (old_size, new_size))

        # don't need to contact remote server for trivial proofs:
        # - empty tree is consistent with everything
        # - everything is consistent with itself
        if old_size == 0 or old_size == new_size:
            d = defer.Deferred()
            d.callback([])
            return d

        deferred_response = self._handler.get(
                self._uri + "/" +
                log_client._GET_STH_CONSISTENCY_PATH,
                params={"first": old_size, "second": new_size})
        deferred_response.addCallback(log_client._parse_consistency_proof,
                                      self.servername)
        return deferred_response
