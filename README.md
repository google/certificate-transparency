certificate-transparency
========================

[![Build Status](https://travis-ci.org/google/certificate-transparency.svg?branch=master)](https://travis-ci.org/google/certificate-transparency)

Auditing for TLS certificates.

## Dependencies ##

 - [OpenSSL](https://www.openssl.org/source/), at least 1.0.0q, preferably 1.0.1l or 1.0.2 (and up)

The checking of SCTs included in the [RFC 6962](http://tools.ietf.org/html/rfc6962) TLS extension is only included in OpenSSL 1.0.2. As of this writing, this version is not yet released, so this means hand building the ```OpenSSL_1_0_2-stable``` branch from the [OpenSSL git repository](https://www.openssl.org/source/repos.html).

 - [CMake](http://www.cmake.org/)
 - [googlemock](https://code.google.com/p/googlemock/) (tested with 1.6.0)

Gmock provides a bundled version of gtest, which will also be used.

Unpack googlemock, but do not build it. Upstream recommends to build a new copy from source for each package to be tested. We follow this advice in our ```Makefile```, which builds gmock/gtest automatically.

Some systems make the googlemock source available as a package; on Debian, this is in the google-mock package, which puts it in ```/usr/src/gmock```. Our ```Makefile``` looks in that location by default, but if your googlemock sources are in a different location, set the ```GMOCKDIR``` environment variable to point at them.

If you are on FreeBSD, you may need to apply the patch in gtest.patch to the gtest subdirectory of gmock.

 - [protobuf](https://github.com/google/protobuf) (tested with 2.4.1)
 - [gflags](https://code.google.com/p/gflags/) (tested with 1.6 and 2.0)
 - [glog](https://code.google.com/p/google-glog/) (tested with 0.3.1)

Make sure to install glog **after** gflags, to avoid linking errors.

 - [Boost](http://www.boost.org/), at least 1.48
 - [sqlite3](http://www.sqlite.org/)
 - [JSON-C](https://github.com/json-c/json-c/), at least 0.11

You can specify a JSON-C library in a non-standard location using the ```JSONCLIBDIR``` environment variable. Version 0.10 would work as well, except the ```json_object_iterator.h``` header is not properly copied when installing. If you can install the missing header manually, it should work.

 - [libevent](http://libevent.org/) (tested with 2.0.21-stable)

You can specify a non-installed locally built library using the ```LIBEVENTDIR``` environment variable to point to the local build. Note that the FreeBSD port version 2.0.21_2 does not appear to work correctly (it only listens on IPv6 for the HTTP server) - for that platform we had to build from the source, specifically commit 6dba1694c89119c44cef03528945e5a5978ab43a.

 - [ldns](http://www.nlnetlabs.nl/projects/ldns/)
 - [ant](http://ant.apache.org/)
 - Python libraries:
  - pyasn1 and pyasn1-modules (optional, needed for ```upload_server_cert.sh```)
  - [dnspython](http://www.dnspython.org/)

## Building ##

You can build the log server by pointing to your custom OpenSSL and/or gtest (if needed):

```
$ make OPENSSLDIR=<path to openssl> GTESTDIR=<path to gtest> LIBEVENTDIR=<path to libevent>
```

If you need to set custom options for your compiler, then you can do this by setting LOCAL_CXXFLAGS. You can also customise the C++ compile in cpp/local.mk.

Once more, use gmake on BSD systems.

## Running Unit Tests ##

Run unit tests with this command

```
$ make OPENSSLDIR=<path to openssl> GTESTDIR=<path to gtest> test
```

If the build still fails because of missing libraries, you may need to set the
environment variable ```LD_LIBRARY_PATH```. On Linux, if you did not change the
default installation path (such as ```/usr/local/lib```), running

```
$ ldconfig
```

or, if needed,

```
$ sudo ldconfig
```

should resolve the problem.

## End-To-End Tests ##

For end-to-end server-client tests, you will need to install Apache
and point the tests to it. See ```test/README``` for how to do so.

## Testing and Logging Options ##

Note that several tests write files on disk. The default directory for
storing temporary testdata is ```/tmp```. You can change
this by setting ```TMPDIR=<tmpdir>``` for make.

End-to-end tests also create temporary certificate and server files in
```test/tmp```. All these files are cleaned up after a successful test run.

For logging options, see
http://google-glog.googlecode.com/svn/trunk/doc/glog.html

By default, unit tests log to stderr, and log only messages with a FATAL level
(i.e., those that result in abnormal program termination).
You can override the defaults with command-line flags.

End-to-end tests log everything at INFO level and above.
