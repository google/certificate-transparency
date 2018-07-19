C++ Log Server Deprecation Notice
---------------------------------

The CT log server implementation in this repository is no longer under
active development. We recommend that new deployments use the new Go
based server, which can handle much bigger trees:

[CT Personality](https://github.com/google/certificate-transparency-go)
[Trillian Log Backend](https://github.com/google/trillian)

The C++ log server implementation in this repository keeps its Merkle tree in
memory, which means two things: 

* Before it can handle requests, it has to load all the leaf hashes, which adds
a significant startup delay. Some log operators have seen startup time upwards
of an hour.
* There's an upper limit on the number of entries a log server can handle,
because it will run out of memory.

Trillian is a new implementation providing these features (and more!):

* Serves from storage not memory, can handle much larger Merkle Trees.
* The underlying log is based on blobs rather than X.509 and such
  structures allowing new applications to be built easily.
* A single log server can serve many Merkle Trees / CT Logs.

CTFE (which is in the certificate-transparency-go repository) then simply
implements the CT API on top of Trillian.

The "classic" Google CT logs (such as Rocketeer, Pilot, Icarus, etc) are written
in C++, they share very little code with the open source C++ log server. This
includes the low level Merkle tree code, and some serialisation.

The newer Google CT logs (such as the Argon and Xenon logs) are Trillian based
and share over ~80% of the code with the open source version. We're running it
ourselves and heavily invested in it working correctly.
