CT DNS Server
=============

The CT DNS Server is an **experimental** implementation of a DNS server that
serves
[CT proofs as DNS records](https://github.com/google/certificate-transparency-rfcs/blob/master/dns/draft-ct-over-dns.md).

The core executable for the DNS server is `cpp/server/ct-dns-server`; this
binary needs to be run alongside a normal CT Log instance.  Moreover, the CT
Log instance must be configured to store its certificate data in an SQLite
database (rather than a LevelDB database) so that the DNS server can safely
share the data.

The key configuration options for the DNS server are:

 - `--port=<port>` specifies the port that the server should respond on.
 - `--domain=<domain>` specifies the top-level domain that the DNS responses
   should be part of.
 - `--db=<sqlitedb>` specifies the certificate database used by the parallel
   CT Log instance, which must be an SQLite database.
