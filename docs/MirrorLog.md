Mirror Log
==========

As well as the main distributed CT Log implementation, this repository also contains code for
a *mirror Log*.  A mirror Log tracks an underlying Log elsewhere, and so does
not allow certificate upload.  The mirror Log is a distributed implementation
like the main Log, and so can act as a more scalable 'front-end' for another Log.


The core executable for the mirror Log is `cpp/server/ct-mirror`, and it
generally needs the same
[configuration and setup](Deployment.md#required-configuration) as the main
Log.  The required additional configuration options for a mirror Log are:

 - `--target_log_uri=<url>` specifies the URL of the target Log to be mirrored.
 - `--target_public_key=<pemfile>` specifies the public key of the target
   Log. (For public Logs tracked by Chrome, public keys are available for
   download from the
   [Known Logs](http://www.certificate-transparency.org/known-logs) page.)
