
Apache With SCT Support
-----------------------

This **deprecated** document describes how to build a version of Apache that
serves SCTs as TLS extensions.  This is no longer necessary, as Apache now
[includes support](https://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html).)

1. Build and install a version of OpenSSL 1.0.2 (a snapshot can be
   found at ftp://ftp.openssl.org/snapshot/). Make sure you build a shared version, for example:
   ```
   $ ./config shared
   ```
   You may want to modify the install path.

2. Apply the patch apache-serverinfo.patch to the Apache source
   (tested with current 2.4.x code). Make sure you have included APR
   in the source (may not be necessary). One way to achieve this is:
   ```
   $ svn co https://svn.apache.org/repos/asf/httpd/httpd/branches/2.4.x httpd-2.4
   $ cd httpd-2.4
   $ svn co https://svn.apache.org/repos/asf/apr/apr/trunk srclib/apr
   ```

3. Configure and build Apache like this:
   ```
   $ ./configure --with-included-apr --enable-ssl --with-ssl=<path to installed openssl>
   $ make
   ```

4. Run Apache:
   ```
   $ ./run_apache_server.sh <path to httpd source> <path to installed openssl>
   ```

5. Test with, say:
   ```
   $ OPENSSLDIR=<path to installed openssl> ./test_running_ssl_server.sh 8124
   ```

