Operating a CT Log
==================

Once a CT log is deployed it needs to be kept operational, particularly if it
is expected to be included in Chrome's
[list of logs](http://www.certificate-transparency.org/known-logs).

Be warned: running a CT log is more difficult than running a normal
database-backed web site, because of the security properties required from a
Log.  Failures that would be recoverable for a normal website &ndash; losing
tiny amounts of logged data, accidentally re-using keys &ndash; will result in
the [failure](https://tools.ietf.org/html/rfc6962#section-7.3) of a CT Log.


 - [Key Management](#key-management)
 - [Monitoring](#monitoring)
    - [Prometheus](#prometheus)
    - [GCM](#gcm)
 - [Logging](#logging)
 - [Tuning](#tuning)
 - [Troubleshooting](#troubleshooting)

Key Management
--------------

Notes:
 - separate keypair for CT use and SSL termination
 - don't re-use the CT test key
 - don't re-use the same CT key for multiple log instances
 - pointer to how to register as a [known log](http://www.certificate-transparency.org/known-logs)

Logging
-------

Tuning
------

 - what are the knobs that can be twiddled, and why?  what stats would tweak in
   what direction?
   
    ct_clustertool -- does what?

Troubleshooting
---------------

 - Any LevelDB tools to explore the database? Safe to do so for a running log?
 - Changing logging levels?
 - Adding/removing nodes ?
    - Geo distribution
    - Start with populated database? Sync?
 - Backups
 - Storing LevelDB directory on a transient per-instance disk 
 - The Log/Mirror binaries will log the git hash from which they were built,
   this can help to verify that they're running the correct version.

Submitting @@@
----------

 - MMD, pubkey -> list
