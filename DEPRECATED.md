C++ Log Server Deprecation Notice
---------------------------------

The CT log server implementation in this repository is no longer under
active development. We recommend that new deployments use the new Go
based server, which can handle much bigger trees:

[CT Personality](https://github.com/google/certificate-transparency-go)
[Trillian Log Backend](https://github.com/google/trillian)

The C++ log server implementation in this repository keeps its Merkle tree in
memory, which means two things: before it can handle requests, it has to load
all the leaf hashes, which adds a significant startup delay (some log operators
have seen startup time upwards of an hour), and also, that there's upper limits
on the number of entries a log server can handle, related to the memory usage.

Trillian provides a storage-based general (based on blobs rather than X.509 and
such structures) Merkle tree platform that is much more scalable. A given
request might have higher latency, due to having to perform lookups into the
storage system, but fairly constant, and in exchange, the startup time is
constant, and the number of entries a log server can contain is vastly higher
(based on available disk storage rather than memory).

CTFE (which is in the certificate-transparency-go repository) then simply
implements the CT API on top of Trillian.

Also, while the "classic" Google CT logs (such as Rocketeer, Pilot, Icarus, etc)
are written in C++, they share very little code with the open source C++ log
server (the low level Merkle tree code, and some serialisation code), but the
newer Google CT logs (such as the Argon and Xenon logs) are Trillian based to a
much greater degree, sharing something like over 80% of the code with the open
source version (there are some interfaces for storage and a few other things
that we have different implementations).
