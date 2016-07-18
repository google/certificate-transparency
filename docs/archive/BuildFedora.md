Package-Based Build on Fedora
=============================

This **deprecated** document describes how to build the CT software using
RPM packaged versions of (most of) the
[software dependencies](README.md#software-dependencies).  This build method
has been superceded by the recommended
[gclient-based method](README.md#building-the-code), which avoids the version
incompatibility issues that affected this method.


Quickstart on Fedora 22
-----------------------

Note: This assumes a Workstation install for x64. The additional dependency
packages that need to be installed may vary if you are starting with a
different base system.

Packaged Dependencies
---------------------

First, install those dependencies of the CT software (and the tools needed to
build them) that are available as packages:

```bash
sudo dnf update
sudo dnf install cmake gcc-g++ libevent-devel golang autoconf pkgconfig \
    json-c-devel gflags-devel glog-devel protobuf-devel leveldb-devel \
    openssl-devel gperftools-devel protobuf-compiler sqlite-devel ant \
    java-1.8.0-openjdk-devel protobuf-java python-gflags protobuf-python \
    python-ecdsa python-mock python-httplib2 git ldns-devel automake \
    libtool shtool libunwind-devel
```

Unpackaged Dependencies
-----------------------

The `gflags` in Fedora is v2.1 and is using the new default namespace option of
‘gflags’ rather than ‘google’ so we need to build our own version.

```bash
git clone https://github.com/gflags/gflags.git
cd gflags
cmake -DGFLAGS_NAMESPACE:STRING=google \
    -DCMAKE_CXX_FLAGS:STRING=-fPIC .
make
cd ..
```

Next, we need `libevhtp` version `1.2.10` which is not packaged in Fedora, so
we build from source:

```bash
wget https://github.com/ellzey/libevhtp/archive/1.2.10.zip
unzip 1.2.10.zip
cd libevhtp-1.2.10/
cmake -DEVHTP_DISABLE_REGEX:STRING=ON -DCMAKE_C_FLAGS:STRING=-fPIC .
make
cd ..
```

And let's get our own Google Test / Google Mock as these vary in incompatible
ways between packaged releases:

```bash
wget https://googlemock.googlecode.com/files/gmock-1.7.0.zip
unzip gmock-1.7.0.zip
```

CT Build
--------

Now, clone the CT repo:

```bash
git clone https://github.com/google/certificate-transparency.git
cd certificate-transparency/
```

One-time setup for Go:

```bash
export GOPATH=$PWD/go
mkdir -p $GOPATH/src/github.com/google
ln -s $PWD $GOPATH/src/github.com/google
go get -v -d ./...
```

Build CT server C++ code:

```bash
./autogen.sh
./configure GTEST_DIR=../gmock-1.7.0/gtest GMOCK_DIR=../gmock-1.7.0 \
    CPPFLAGS="-I../libevhtp-1.2.10 -I../libevhtp-1.2.10/evthr \
    -I../libevhtp-1.2.10/htparse -I../gflags/include" \
    LDFLAGS=”-L../libevhtp-1.2.10 -L../gflags/lib”
make check
```

The remainder of the Java, Go and Python steps should be very similar to those
[documented for Ubuntu](BuildUbuntu.md#ct-build).
