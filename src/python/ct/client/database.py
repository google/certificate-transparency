import abc

class Error(Exception):
    pass

class KeyError(Error):
    """Raised when key constraints are violated."""
    pass

class OperationalError(Error):
    """Raised when a database operation fails, e.g., because of a timeout.
    May be raised by all Database operations including __init__"""
    pass

class Database(object):
    """Database interface for storing client-side CT data."""
    __metaclass__ = abc.ABCMeta

    # The largest BSON can handle
    timestamp_max = 2**63-1

    @abc.abstractmethod
    def add_log(self, metadata):
        """Store log metadata. This creates the necessary mappings between
        tables so all logs must be explicitly added."""
        raise NotImplementedError

    def logs(self):
        """A generator that yields all currently known logs."""
        raise NotImplementedError

    @abc.abstractmethod
    def store_sth(self, log_server, sth):
        """Store the STH in the database.
        Will store the STH with a unique ID unless an exact copy already exists.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_latest_sth(self, log_server):
        """"Get the STH with the latest timestamp."""
        raise NotImplementedError

    @abc.abstractmethod
    def scan_latest_sth_range(self, log_server, start=0, end=timestamp_max,
                              limit=0):
        """Scan STHs by timestamp
        Args:
            logid: CT log to scan
            start: earliest timestamp
            end: latest timestamp
            limit: maximum number of entries to return. Default is no limit.
        Yields:
            the STHs in descending order of timestamps
        Note the scan may be keeping the database connection open until the
        generator is exhausted.
        """
        raise NotImplementedError
