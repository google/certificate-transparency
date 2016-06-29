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

The capacity and resilience of a Log cluster can be increased by running
additional instances of `ct-server`; each instance communicates with the `etcd`
cluster to discover information about the Log cluster, so does not need
individual configuration.

However, the distributed CT Log relies on configuration stored in `etcd` to
govern how many Log instances are _required_ for serving.  This is configured
using the `ClusterConfig` [protobuf](../proto/ctproto) message, which includes:

 - `minimum_serving_nodes`: Minimum number of available Log instances (defaults
   to 2); an STH must have been replicated to at least this many nodes in order
   to be eligible as the overall cluster STH.
 - `minimum_serving_fraction`: Minimum fraction of Log instances that must be
   available to serve a given STH (default 0.75).

The Log configuration also includes the `etcd_reject_add_pending_threshold`
config value (default 30000), which limits how many certificate chains can be
pending (added, but not yet integrated) at once.  This should be large enough
to accomodate the maximum number of certificates that could arrive during a
maximum-merge-delay (MMD) period, but not so large that an adversary spamming
the Log could cause problems.

These configuration values can be changed using the `cpp/tools/ct-clustertool`
tool, with the `set-config --cluster_config=<ascii-proto-file>` options; the
input file is an text format protobuf file, for example:

```
minimum_serving_nodes: 2
minimum_serving_fraction: 0.75
```

Because these limits affect the ability of the Log to operate, **monitoring and
alerting rules should be set up** to detect when the limits are near to being
reached.


Adjusting a Running Cluster
---------------------------

Because the `etcd` cluster handles synchronization between the CT Log server
instances, it is possible to adjust a running cluster by bringing
individual `ct-server` instance down or up.  However, to ensure that the cluster
as a whole continues to operate during the process, only a small number
of instances should be brought down at a time.

For example, upgrading the CT Log software could be done safely by bringing down
each instance of the old version and replacing it with an instance of the new
version one at a time (as long as the [cluster configuration](#tuning) allows
this).

For the [Docker-based deployment](Deployment.md#docker-setup), the
[`update_log.sh` script](Deployment.md#updating-log-software) handles this; it
checks that each instance of the new version is up and responding before moving
on to replacement of the next instance.

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
