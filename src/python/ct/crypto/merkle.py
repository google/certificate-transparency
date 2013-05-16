import hashlib

class TreeHasher(object):
    def __init__(self, hashfunc=hashlib.sha256):
        self.hashfunc = hashfunc

    def __repr__(self):
        return "%r(hash function: %r)" % (self.__class__.__name__,
                                          self.hashfunc)

    def __str__(self):
        return "%s(hash function: %s)" % (self.__class__.__name__,
                                          self.hashfunc)

    def hash_empty(self):
        hasher = self.hashfunc()
        return hasher.digest()

    def hash_leaf(self, data):
        hasher = self.hashfunc()
        hasher.update('\x00' + data)
        return hasher.digest()

    def hash_children(self, left, right):
        hasher = self.hashfunc()
        hasher.update('\x01' + left + right)
        return hasher.digest()
