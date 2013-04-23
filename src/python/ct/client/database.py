import abc

class Database(object):
    """Database interface for storing client-side CT data."""
    __metaclass__ = abc.ABCMeta

    # The largest BSON can handle
    timestamp_max = 2**63-1
    
    @abc.abstractmethod
    def store_sth(self, sth):
        """Store the STH in the database.
    
        Will store the STH with a unique ID unless an exact copy already exists.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_latest_sth(self, logid):
        """"Get the latest STH by STH timestamp."""
        raise NotImplementedError

    @abc.abstractmethod
    def scan_latest_sth_range(self, logid, start=0, end=timestamp_max, limit=0):
        """Scan STHs by timestamp
        Args:
            logid: CT log to scan
            start: earliest timestamp
            end: latest timestamp
            limit: maximum number of entries to return. Default is no limit.
        Returns:
            A generator that yields the STHs in descending order of timestamps
        """
        raise NotImplementedError
