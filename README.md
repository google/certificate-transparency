certificate-transparency
========================

Auditing for TLS certificates.

## Dependencies ##

 - [OpenSSL](https://www.openssl.org/source/), at least 1.0.0, preferably 1.0.2 (and up)

The checking of SCTs included in the [RFC 6962](http://tools.ietf.org/html/rfc6962) TLS extension is only included in OpenSSL 1.0.2. As of this writing, this version is not yet released, so this means hand building the ```OpenSSL_1_0_2-stable``` branch from the [OpenSSL git repository](https://www.openssl.org/source/repos.html).

 - [CMake](http://www.cmake.org/)
 - [googletest](https://code.google.com/p/googletest/) (tested with 1.6.0)

Unpack googletest, but do not build it. Upstream recommends to build a new copy from source for each package to be tested. We follow this advice in our ```Makefile```, which builds gtest automatically.

Some systems make the googletest source available as a package; on Debian, this is in the libgtest-dev package, which puts it in ```/usr/src/gtest```. Our ```Makefile``` looks in that location by default, but if your googletest sources are in a different location, set the ```GTESTDIR``` environment variable to point at them.

 - [protobuf](https://code.google.com/p/protobuf/) (tested with 2.4.1)
 - [gflags](https://code.google.com/p/gflags/) (tested with 1.6 and 2.0)
 - [glog](https://code.google.com/p/google-glog/) (tested with 0.3.1)

Make sure to install glog **after** gflags, to avoid linking errors.

 - [Boost](http://www.boost.org/), at least 1.48
 - [sqlite3](http://www.sqlite.org/)
 - [cURL](http://curl.haxx.se/) (tested with 7.36.0)

There are multiple Debian packages for this library (```libcurl4-gnutls-dev```, ```libcurl4-nss-dev```, or ```libcurl4-openssl-dev```, for example), any of them should do, but if you compile your own version of OpenSSL, it will conflict with the one cURL uses.

To avoid this, either avoid the package that OpenSSL (```libcurl4-openssl-dev```), or you can build your own cURL that uses the same OpenSSL that you built, instead of the packaged version.

 - [JSON-C](https://github.com/json-c/json-c/), at least 0.11

You can specify a JSON-C library in a non-standard location using the ```JSONCLIBDIR``` environment variable. Version 0.10 would work as well, except the ```json_object_iterator.h``` header is not properly copied when installing. If you can install the missing header manually, it should work.

 - [cpp-netlib](http://cpp-netlib.org/) (tested with 0.10.1)

This library cannot be installed using ```make install```. Use the ```CPPNETLIBDIR``` environment variable to point to the local build.

 - [ldns](http://www.nlnetlabs.nl/projects/ldns/)
 - [ant](http://ant.apache.org/)
 - Python libraries:
  - pyasn1 and pyasn1-modules (optional, needed for ```upload_server_cert.sh```)
  - [dnspython](http://www.dnspython.org/)

## Building ##

You can build the log server by pointing to your custom OpenSSL and/or gtest (if needed):

```
$ make OPENSSLDIR=<path to openssl> GTESTDIR=<path to gtest> CPPNETLIBDIR=<path to cpp-netlib>
```

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
