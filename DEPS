deps = {
     "gflags":  	 			 "https://github.com/gflags/gflags.git@v2.1.2",
     "glog": 			 			 "https://github.com/google/glog.git@v0.3.4",
     "gperftools": 			 "https://github.com/gperftools/gperftools.git@gperftools-2.4",
     "googlemock": 			 "https://github.com/google/googlemock.git@release-1.7.0",
     "googlemock/gtest": "https://github.com/google/googletest.git@release-1.7.0",
     "json-c": 					 "https://github.com/json-c/json-c.git@json-c-0.12-20140410",
     "ldns": 						 "git://git.nlnetlabs.nl/ldns@release-1.6.17",
     "leveldb": 				 "https://github.com/google/leveldb.git@v1.18",
     "libevent": 				 "https://github.com/libevent/libevent.git@release-2.0.22-stable",
     "libevhtp": 				 "https://github.com/ellzey/libevhtp.git@ba4c44eed1fb7a5cf8e4deb236af4f7675cc72d5",
     "openssl": 				 "https://github.com/benlaurie/openssl.git@fd5d2ba5e09f86e9ccf797dddd2d09ac8e197e35", # 1.0.2-freebsd
     "protobuf/gtest": 	 "https://github.com/google/googletest.git@release-1.5.0",
     "protobuf": 			 	 "https://github.com/google/protobuf.git@v2.6.1",
     # Randomly chosen github mirror
     "sqlite3-export": 	 "http://repo.or.cz/sqlite-export.git",
     "sqlite3": 				 "http://repo.or.cz/sqlite.git@version-3.8.10.1",
		 "tcmalloc":				 "https://github.com/gperftools/gperftools.git@gperftools-2.4"
}

# Can't use deps_os for this because it doesn't know about freebsd :/
deps_overrides = {
  "freebsd10": {
     "googlemock": 			 "https://github.com/AlCutter/googlemock-fbsd.git@1.7.0",
     "googlemock/gtest": "https://github.com/AlCutter/googletest-fbsd.git@1.7.0",
     "protobuf/gtest": "https://github.com/benlaurie/googletest.git@1.5.0-fix",
     "protobuf": "https://github.com/benlaurie/protobuf.git@2.6.1-fix",
     "glog": "https://github.com/benlaurie/glog.git@0.3.4-fix",
     "ldns": "https://github.com/benlaurie/ldns.git@1.6.17-fix",
  },
  "darwin": {
     "ldns": "https://github.com/benlaurie/ldns.git@1.6.17-fix",
  }
}

make_os = {
	"freebsd10": "gmake",
	"darwin": "gnumake"
}

import os
import sys

print "Host platform is %s" % sys.platform
if sys.platform in deps_overrides:
  print "Have %d overrides for platform" % len(deps_overrides[sys.platform])
  deps.update(deps_overrides[sys.platform])
if sys.platform in make_os:
	make = make_os[sys.platform]
else:
	make = "make"
print "Using make %s" % make

here = os.getcwd()
install = os.path.join(here, "install")

hooks = [
    {
        "name": "deps",
        "pattern": ".",
        "action": [ make, "-f", os.path.join(here, "certificate-transparency/build.gclient"), "INSTALL_DIR=%s"%install],
    },
]
