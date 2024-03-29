certificate-transparency: Auditing for TLS certificates
=======================================================

This repository is no longer actively maintained.

The CT log server and client written in Go are available at 
[google/trillian](https://github.com/google/trillian) and 
[google/certificate-transparency-go](https://github.com/google/certificate-transparency-go).

---

 - [Introduction](#introduction)
 - [Build Quick Start](#build-quick-start)
 - [Code Layout](#code-layout)
 - [Building the code](#building-the-code)
    - [Build Dependencies](#build-dependencies)
    - [Software Dependencies](#software-dependencies)
 - [Build Troubleshooting](#build-troubleshooting)
    - [Compiler Warnings/Errors](#compiler-warnings-errors)
    - [Working on a Branch](#working-on-a-branch)
 - [Testing the code](#testing-the-code)
    - [Unit Tests](#unit-tests)
    - [Testing and Logging Options](#testing-and-logging-options)
 - [Deploying a Log](#deploying-a-log)
 - [Operating a Log](#operating-a-log)

Introduction
------------

This repository holds open-source code for functionality related
to [certificate transparency](https://www.certificate-transparency.org/) (CT).
The main areas covered are:

 - A collection of client tools and libraries for interacting with a CT Log, in
   various programming languages.

The supported platforms are:

 - **Linux**: tested on Ubuntu 14.04; other variants (Fedora 22, CentOS 7) may
   require tweaking of [compiler options](#build-troubleshooting).
 - **OS X**: version 10.10
 - **FreeBSD**: version 10.*

C++ Log Server Deprecation Notice
---------------------------------

The CT log server implementation which used to be in this repository is no
longer under active development. We recommend that new deployments use the new
Go based server, which can handle much larger Merkle trees:

[CT Personality](https://github.com/google/certificate-transparency-go)
[Generic Backend](https://github.com/google/trillian)

For more information on why we recommend this see the
[Deprecation Notes](DEPRECATED.md)

N.B. This notice refers to the servers only, not the other client code in this
repository.


Build Quick Start
-----------------

First, ensure that the build machine has all of the required [build dependencies](#build-dependencies).
Then use
[gclient](https://www.chromium.org/developers/how-tos/depottools#TOC-gclient) to
retrieve and build the [other software](#software-dependencies) needed by the Log,
and then use (GNU) `make` to build and test the CT code:

```bash
export CXX=clang++ CC=clang
mkdir ct  # or whatever directory you prefer
cd ct
gclient config --name="certificate-transparency" https://github.com/google/certificate-transparency.git
gclient sync --disable-syntax-validation  # retrieve and build dependencies
# substitute gmake or gnumake below if that's what your platform calls it:
make -C certificate-transparency check  # build the CT software & self-test
```

Code Layout
-----------

The source code is generally arranged according to implementation language, in
the `cpp` and `python` subdirectories. ([Java](https://github.com/google/certificate-transparency-java)
and [Go](https://github.com/google/certificate-transparency-go)
code are in separate repositories.)


The key subdirectories are:

 - For the main distributed CT Log itself:
   - `cpp/log`: Main distributed CT Log implementation.
   - `cpp/merkletree`: Merkle tree implementation.
   - `cpp/monitoring`: Code to export operation statistics from CT Log.
 - Client code for accessing a CT Log instance:
   - `cpp/client`: CT Log client code in C++
   - `python/ct`: CT Log client code in Python

Building the Code
-----------------

The CT software in this repository relies on a number of other
[open-source projects](#software-dependencies), and we recommend that:

 - The CT software should be built using local copies of these dependencies
   rather than installed packages, to prevent version incompatibilities.
 - The dependent libraries should be statically linked into the CT binaries,
   rather than relying on dynamically linked libraries that may be different in
   the deployed environment.

The supported build system uses the
[gclient](https://www.chromium.org/developers/how-tos/depottools#TOC-gclient)
tool from the Chromium project to handle these requirements and to ensure a
reliable, reproducible build.  Older build instructions for using
[Ubuntu](docs/archive/BuildUbuntu.md) or
[Fedora](docs/archive/BuildFedora.md) packages and for
[manually building dependencies from source](docs/archive/BuildSrc.md) are no
longer supported.

Within a main top-level directory, gclient handles the process of:

 - generating subdirectories for each dependency
 - generating a subdirectory for for the CT Log code itself
 - building all of the dependencies
 - installing the built dependencies into an `install/` subdirectory
 - configuring the CT build to reference the built dependencies.

Under the covers, this gclient build process is controlled by:

 - The master [DEPS](DEPS) file, which configures the locations and versions
   of the source code needed for the dependencies, and which hooks onto ...
 - The makefiles in the [build/](build) subdirectory, which govern the build
   process for each dependency, ensuring that:
     - Static libraries are built.
     - Built code is installed into the local `install/` directory, where it
       is available for the build of the CT code itself.


### Build Dependencies

The following tools are needed to build the CT software and its dependencies.

 - [depot_tools](https://www.chromium.org/developers/how-tos/install-depot-tools)
 - autoconf/automake etc.
 - libtool
 - shtool
 - clang++ (>=3.4)
 - cmake (>=v3.1.2)
 - git
 - GNU make
 - Tcl
 - pkg-config
 - Python 2.7

The exact packages required to install these tools depends on the platform.
For a Debian-based system, the relevant packages are:
`autoconf automake libtool shtool cmake clang git make tcl pkg-config python2.7`

### Software Dependencies

The following collections of additional software are used by the main CT
Log codebase.

 - Google utility libraries:
    - [gflags](https://github.com/gflags/gflags): command-line flag handling
    - [glog](https://github.com/google/glog): logging infrastructure, which
      also requires libunwind.
    - [Google Mock](https://github.com/google/googlemock.git): C++ test framework
    - [Google Test](https://github.com/google/googletest.git): C++ mocking
      framework
    - [Protocol Buffers](https://developers.google.com/protocol-buffers/):
      language-neutral data serialization library
    - [tcmalloc](http://goog-perftools.sourceforge.net/doc/tcmalloc.html):
      efficient `malloc` replacement optimized for multi-threaded use
 - Other utility libraries:
    - [libevent](http://libevent.org/): event-processing library
    - [libevhtp](https://github.com/ellzey/libevhtp): HTTP server
      plug-in/replacement for libevent
    - [json-c](https://github.com/json-c/json-c): JSON processing library
    - [libunwind](http://www.nongnu.org/libunwind/): library for generating
      stack traces
    - [OpenSSL](https://github.com/google/googletest.git): default
      cryptography library.


Build Troubleshooting
---------------------

### Compiler Warnings/Errors

The CT C++ codebase is built with the Clang `-Werror` flag so that the
codebase stays warning-free.  However, this can cause build errors when
newer/different versions of the C++ compiler are used, as any newly created
warnings are treated as errors.  To fix this, add the appropriate
`-Wno-error=<warning-name>` option to `CXXFLAGS`.

For example, on errors involving unused variables try using:

```bash
CXXFLAGS="-O2 -Wno-error=unused-variable" gclient sync
```

If an error about an unused typedef in a `glog` header file occurs, try this:

```bash
CXXFLAGS="-O2 -Wno-error=unused-variable -Wno-error=unused-local-typedefs" gclient sync
```

When changing `CXXFLAGS` it's safer to remove the existing build directories
in case not all dependencies are properly accounted for and rebuilt. If
problems persist, check that the Makefile in `certificate-transparency`
contains the options that were passed in `CXXFLAGS`.

### Working on a Branch

If you're trying to clone from a branch on the CT repository then you'll need
to substitute the following command for the `gclient config` command
[above](#build-quick-start), replacing `branch` as appropriate

```bash
gclient config --name="certificate-transparency" https://github.com/google/certificate-transparency.git@branch
```

Then continue the [build process](#build-quick-start) with the `gclient sync` step.


Testing the Code
----------------

### Unit Tests

The unit tests for the CT code can be run with the `make check` target of
`certificate-transparency/Makefile`.

## Testing and Logging Options ##

Note that several tests write files on disk. The default directory for
storing temporary testdata is `/tmp`. You can change this by setting
`TMPDIR=<tmpdir>` for make.

End-to-end tests also create temporary certificate and server files in
`test/tmp`. All these files are cleaned up after a successful test
run.

For logging options, see the
[glog documentation](http://htmlpreview.github.io/?https://github.com/google/glog/blob/master/doc/glog.html).

By default, unit tests log to `stderr`, and log only messages with a FATAL
level (i.e., those that result in abnormal program termination).  You can
override the defaults with command-line flags.
