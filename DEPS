deps = {
     "googlemock": "http://googlemock.googlecode.com/svn/tags/release-1.7.0",
     "googlemock/gtest": "http://googletest.googlecode.com/svn/tags/release-1.7.0",
     "openssl": "https://github.com/benlaurie/openssl.git@fd5d2ba5e09f86e9ccf797dddd2d09ac8e197e35", # 1.0.2-freebsd
#     "protobuf": "https://github.com/google/protobuf.git@v2.6.1",
     "protobuf": "https://github.com/benlaurie/protobuf.git@2.6.1-fix",     
#     "protobuf/gtest": "http://googletest.googlecode.com/svn/tags/release-1.5.0",
     "protobuf/gtest": "https://github.com/benlaurie/googletest.git@1.5.0-fix",
     "libevent": "https://github.com/libevent/libevent.git@release-2.0.22-stable",
     "gflags": "https://github.com/gflags/gflags.git@v2.1.2",
#     "glog": "https://github.com/google/glog.git@v0.3.4",
     "glog": "https://github.com/benlaurie/glog.git@0.3.4-fix",
#     "ldns": "git://git.nlnetlabs.nl/ldns@release-1.6.17",
     "ldns": "https://github.com/benlaurie/ldns.git@1.6.17-fix",
     # Randomly chosen github mirror
     "sqlite3-export": "http://repo.or.cz/sqlite-export.git",
     "sqlite3": "http://repo.or.cz/sqlite.git@version-3.8.10.1",
     "leveldb": "https://github.com/google/leveldb.git@v1.18",
}

import os
here = os.getcwd()
install = os.path.join(here, "install")

hooks = [
    {
        "name": "openssl",
        "pattern": "^openssl/",
        "action": [ "make", "-C", "openssl", "-f", os.path.join(here, "certificate-transparency/build/Makefile.openssl"), "INSTALL=" + install ],
    },
    {
        "name": "protobuf",
        "pattern": "^protobuf/",
        "action": [ "certificate-transparency/build/rebuild_protobuf" ],
    },
    {
        "name": "libevent",
        "pattern": "^libevent/",
        "action": [ "certificate-transparency/build/rebuild_libevent" ],
    },
    {
        "name": "gflags",
        "pattern": "^gflags/",
        "action": [ "make", "-C", "gflags", "-f", os.path.join(here, "certificate-transparency/build/Makefile.gflags") ],
    },
    {
        "name": "glog",
        "pattern": "^glog/",
        "action": [ "make", "-C", "glog", "-f",  os.path.join(here, "certificate-transparency/build/Makefile.glog") ],
    },
    {
        "name": "ldns",
        "pattern": "^ldns/",
        "action": [ "make", "-C", "ldns", "-f",  os.path.join(here, "certificate-transparency/build/Makefile.ldns") ],
    },
    {
        "name": "sqlite3",
        "pattern": "^sqlite3/",
        "action": [ "make", "-C", "sqlite3", "-f",  os.path.join(here, "certificate-transparency/build/Makefile.sqlite3") ],
    },
    {
        "name": "leveldb",
        "pattern": "^leveldb/",
        "action": [ "make", "-C", "leveldb", "-f",  os.path.join(here, "certificate-transparency/build/Makefile.leveldb") ],
    },
    # Do this last
    {
        "name": "ct",
        "pattern": ".",
        "action": [ "certificate-transparency/build/rebuild" ],
    }
]
