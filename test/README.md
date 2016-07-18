End-To-End Test
===============

The `sslconnect_test.sh` script does an end-to-end test for the CT log.
This involves:

 - creating a server certificate
 - sending the certificate to the log server
 - receiving a log proof
 - setting up Apache to serve the certificate and the log proof
 - verifying the log proof.

To run `sslconnect_test.sh`, you will need to do the following:

1. Compile the CT log server and client libraries, following the instructions
   in the top-level [README](../README.md).

2. Install Apache, which is needed to run a test SSL server; on Debian based
   systems installing the `apache2` package should suffice.  You may also need
   to modify `httpd-local.conf`; see the
   [`httpd-common.conf`](httpd-common.conf) file for tips.  (Historical
   instructions for
   [building CT support into Apache](../docs/archive/ApacheSctSupport.md) are
   no longer necessary, as Apache now
   [includes support](https://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html).)

3. From this `test/` directory, run `./sslconnect_test.sh`.  This will
   initially run client regression tests with existing certificates. Next,
   it will generate fresh test certificates and test:

    - the submission of certificates and precertificates to the log server
    - the retrieval of initial Signed Certificate Timestamps
    - serving Signed Certificate Timestamps in a TLS handshake
    - retrieving audit proofs for those SCTs from the log server.

The final output from the tests should be something like:

```
PASSED 38 tests
FAILED 0 tests
```

