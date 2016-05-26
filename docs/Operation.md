Operating a CT Log
==================

Once a CT log is deployed it needs to be kept operational, particularly if it
is expected to be included in Chrome's
[list of logs](http://www.certificate-transparency.org/known-logs).

Be warned: running a CT log is more difficult than running a normal
database-backed web site, because of the security properties required from a Log
&ndash; running a public Log involves a commitment to reliably store all (valid)
uploaded certificates and include them in the tree within a specified period.
This means that failures that would be recoverable for a normal website &ndash;
losing tiny amounts of logged data, accidentally re-using keys &ndash; will
result in the [failure](https://tools.ietf.org/html/rfc6962#section-7.3) of a CT
Log.

 - [Key Management](#key-management)
 - [Tuning](#tuning)
 - [Adjusting a Running Cluster](#adjusting-a-running-cluster)
    - [Changing Software Versions](#changing-software-versions)
    - [Changing Cluster Size](#changing-cluster-size)
 - [Troubleshooting](#troubleshooting)
 - [Submitting a Log](#submitting-a-log)

Key Management
--------------

A CT Log is a cryptographic entity that signs data using a
[private key](https://tools.ietf.org/html/rfc6962#section-2.1.4).  This key is
needed by all of the distributed Log instances, but also needs to be kept
secure.  In particular:

 - The CT Log key must not be re-used for distinct Logs.
    - Note that the [Docker images](Deployment.md#image-creation) for the CT Log
      software include a baked-in test key; this needs to be replaced for a real
      Log.
 - The CT Log key should not be re-used for HTTPS/TLS termination.

The corresponding public key is needed in order to register as a
[known log](http://www.certificate-transparency.org/known-logs)


Tuning
------

TODO what are the knobs that can be twiddled, and why?  what monitored
statistics would mean that knobs should be moved, and in what direction?


Adjusting a Running Cluster
---------------------------

### Changing Software Versions

TODO describe more here, cf. [Docker instructions](Deployment.md#updating-log-software)

### Changing Cluster Size

TODO describe how to scale the log up/down safely

Troubleshooting
---------------

TODO:
 - Any LevelDB tools to explore the database? Safe to do so for a running log?
 - Changing logging levels? What to look for in logs, and where?
   - The Log/Mirror binaries will log the git hash from which they were built,
     this can help to verify that they're running the correct version.
 - Backups?
 - Don't store LevelDB directory on a transient per-instance disk!


Submitting a Log
----------------

TODO: describe how to get a Log added to the list of known logs.  Inputs are:

 - The URL for the Log.
 - The public key for the Log.
 - The maximum merge delay (MMD) that the Log has committed to.
