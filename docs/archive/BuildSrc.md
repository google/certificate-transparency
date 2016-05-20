Manual Depedency Builds from Source
===================================

This **deprecated** document describes how to build the CT software using
individual source packages.  This build method has been superceded by the
recommended [gclient-based method](README.md#building-the-code), which
effectively automates the process described here.

Dependency Builds
-----------------

 - [OpenSSL](https://www.openssl.org/source/), at least 1.0.0q,
   preferably 1.0.1l or 1.0.2 (and up)

The checking of SCTs included in the
[RFC 6962](http://tools.ietf.org/html/rfc6962) TLS extension is only
included in OpenSSL 1.0.2. As of this writing, this version is not yet
released, so this means hand building the `OpenSSL_1_0_2-stable`
branch from the
[OpenSSL git repository](https://www.openssl.org/source/repos.html).

 - [googlemock](https://github.com/google/googlemock) (tested with 1.7.0)

Gmock provides a bundled version of gtest, which will also be used.

Unpack googlemock, but do not build it. Upstream recommends to build a
new copy from source for each package to be tested. We follow this
advice in our `Makefile`, which builds gmock/gtest automatically.

Some systems make the googlemock source available as a package; on
Debian, this is in the google-mock package, which puts it in
`/usr/src/gmock`. Our `Makefile` looks in that location by default,
but if your googlemock sources are in a different location, set the
`GMOCK_DIR` environment variable to point at them.

If you are on FreeBSD, you may need to apply the patch in gtest.patch
to the gtest subdirectory of gmock.

 - [protobuf](https://github.com/google/protobuf) (tested with 2.5.0)
 - [gflags](https://github.com/gflags/gflags) (tested with 1.6
   and 2.0)
 - [glog](https://github.com/google/glog) (tested with 0.3.1)

Make sure to install glog **after** gflags, to avoid linking errors.

 - [sqlite3](http://www.sqlite.org/)
 - [leveldb](https://github.com/google/leveldb)
 - [JSON-C](https://github.com/json-c/json-c/), at least 0.11

You can specify a JSON-C library in a non-standard location using the
`JSONCLIBDIR` environment variable. Version 0.10 would work as well,
except the `json_object_iterator.h` header is not properly copied when
installing. If you can install the missing header manually, it should
work.

 - [libevent](http://libevent.org/) (tested with 2.0.21-stable)
 - [libevhtp](https://github.com/ellzey/libevhtp) (tested with 1.2.10)
 If building libevhtp from source, you may need to disable the regex support
 with the following cmake flag: `-DEVHTP_DISABLE_REGEX:STRING=ON`

You can specify a non-installed locally built library using the
`LIBEVENTDIR` environment variable to point to the local build. Note
that the FreeBSD port version 2.0.21_2 does not appear to work
correctly (it only listens on IPv6 for the HTTP server) - for that
platform we had to build from the source, specifically commit
6dba1694c89119c44cef03528945e5a5978ab43a.

 - [ldns](http://www.nlnetlabs.nl/projects/ldns/)
 - [ant](http://ant.apache.org/)
 - Python libraries:
  - pyasn1 and pyasn1-modules (optional, needed for `upload_server_cert.sh`)
  - [dnspython](http://www.dnspython.org/)

CT Build
--------

You can build the log server with the following commands:

    $ ./autogen.sh  # only necessary if you're building from git
    $ ./configure
    $ make

You can give the `configure` script extra parameters, to set
compilation flags, or point to custom versions of some dependencies
(notably, googlemock often needs this). For example, to compile with
Clang, using googlemock in `$HOME/gmock`, and a custom libevent in
`$HOME/libevent`:

    $ ./configure CXX=clang++ GMOCK_DIR=$HOME CPPFLAGS="-I$HOME/libevent/include" LDFLAGS="-L$HOME/libevent/.libs"

Running `./configure --help` provides more information about various
variables that can be set.


CT Unit Tests
-------------

Run unit tests with this command

    $ make check

If the build still fails because of missing libraries, you may need to
set the environment variable `LD_LIBRARY_PATH`. On Linux, if you did
not change the default installation path (such as `/usr/local/lib`),
running

    $ ldconfig

or, if needed,

    $ sudo ldconfig

should resolve the problem.
