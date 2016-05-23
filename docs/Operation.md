Operating a CT Log
==================

Once a CT log is deployed it needs to be kept operational, particularly if it is expected
to be included in Chrome's [list of logs](http://www.certificate-transparency.org/known-logs)

 - [Key Management](#key-management)
 - [Monitoring](#monitoring)
    - [Prometheus](#prometheus)
    - [GCM](#gcm)
 - [Logging](#logging)
 - [Troubleshooting](#troubleshooting)

Key Management
--------------

Notes:
 - separate keypair for CT use and SSL termination
 - don't re-use the CT test key
 - don't re-use the same CT key for multiple log instances
 - pointer to how to register as a [known log](http://www.certificate-transparency.org/known-logs)

Monitoring
----------

### Prometheus

### GCM

Logging
-------

Troubleshooting
---------------
