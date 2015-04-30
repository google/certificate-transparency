deps = {
     "googlemock": "http://googlemock.googlecode.com/svn/tags/release-1.7.0",
     "openssl": "https://github.com/openssl/openssl.git@OpenSSL_1_0_2a",
     "protobuf": "https://github.com/google/protobuf.git@v2.6.1",
     "libevent": "https://github.com/libevent/libevent.git@release-2.0.22-stable",
     "gflags": "https://github.com/gflags/gflags.git@v2.1.2",
     "glog": "https://github.com/google/glog.git@v0.3.4",
     "ldns": "git://git.nlnetlabs.nl/ldns@release-1.6.17",
}

hooks = [
    {
        "name": "openssl",
        "pattern": "^openssl/",
        "action": [ "certificate-transparency/build/rebuild_openssl" ],
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
        "action": [ "make", "-C", "gflags", "-f", "certificate-transparency/build/Makefile.gflags" ],
    },
    {
        "name": "glog",
        "pattern": "^glog/",
        "action": [ "make", "-C", "glog", "-f", "certificate-transparency/build/Makefile.glog" ],
    },
    {
        "name": "ldns",
        "pattern": "^ldns/",
        "action": [ "make", "-C", "ldns", "-f", "certificate-transparency/build/Makefile.ldns" ],
    },
    # Do this last
    {
        "name": "ct",
        "pattern": ".",
        "action": [ "certificate-transparency/build/rebuild" ],
    }
]
