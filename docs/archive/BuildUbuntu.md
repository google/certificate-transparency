Package-Based Build on Ubuntu
=============================

This **deprecated** document describes how to build the CT software using
Debian packaged versions of (most of) the
[software dependencies](README.md#software-dependencies).  This build method
has been superceded by the recommended
[gclient-based method](README.md#building-the-code), which avoids the version
incompatibility issues that affected this method.

Packaged Dependencies
---------------------

The following steps will checkout the code and build it on a clean Ubuntu
14.04 LTS installation.  It has also been tested on an Ubuntu 15.04
installation.

First, install those dependencies of the CT software (and the tools needed to
build them) that are available as packages:

    sudo apt-get update -qq
    sudo apt-get install -qq unzip cmake g++ libevent-dev golang-go autoconf pkg-config \
        libjson-c-dev libgflags-dev libgoogle-glog-dev libprotobuf-dev libleveldb-dev \
        libssl-dev libgoogle-perftools-dev protobuf-compiler libsqlite3-dev ant openjdk-7-jdk \
        libprotobuf-java python-gflags python-protobuf python-ecdsa python-mock \
        python-httplib2 git libldns-dev

Unpackaged Dependencies
-----------------------

Next, we need `libevhtp` version `1.2.10` which is not packaged in Ubuntu yet,
so we build from source:

    wget https://github.com/ellzey/libevhtp/archive/1.2.10.zip
    unzip 1.2.10.zip
    cd libevhtp-1.2.10/
    cmake -DEVHTP_DISABLE_REGEX:STRING=ON -DCMAKE_C_FLAGS:STRING=-fPIC .
    make
    cd ..

And let's get our own Google Test / Google Mock as these vary in incompatible
ways between packaged releases:

    wget https://googlemock.googlecode.com/files/gmock-1.7.0.zip
    unzip gmock-1.7.0.zip

CT Build
--------

Now, clone the CT repo:

    git clone https://github.com/google/certificate-transparency.git
    cd certificate-transparency/

One-time setup for Go:

    export GOPATH=$PWD/go
    mkdir -p $GOPATH/src/github.com/google
    ln -s $PWD $GOPATH/src/github.com/google
    go get -v -d ./...

Build CT server C++ code:

    ./autogen.sh
    ./configure GTEST_DIR=../gmock-1.7.0/gtest GMOCK_DIR=../gmock-1.7.0 \
        CPPFLAGS="-I../libevhtp-1.2.10 -I../libevhtp-1.2.10/evthr \
        -I../libevhtp-1.2.10/htparse" LDFLAGS=-L../libevhtp-1.2.10
    make check

Build and test Java code:

    ant build test

Build and test Python code:

    make -C python test

Build and test Go code:

    go test -v ./go/...
