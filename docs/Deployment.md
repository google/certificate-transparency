Deploying a CT Log
==================

A deployed CT Log requires more than just the CT log code contained in this
repository.  This document describes the additional software and setup
required to get from a [fully built](../README.md#building-the-code)
collection of CT software to a running Log.

This document includes:
 - Two methods for setting up a CT Log:
    - [Instructions for manually setting up](#manual-setup) a Log instance on
      individual machines.
    - [Instructions for using Docker images](#docker-setup) to make the setup
      process easier and more automatic.
 - Common
   [instructions for checking basic operation](#checking-basic-operation) of
   the Log.

If you're planning to operate a trusted CT Log (rather than simply
experimenting/playing with the code) then you should expect to understand all
of the information in the manual version &ndash; even if you use the Docker
variant for deployment convenience.

<img src="images/SystemDiagram.png" width="650">

As shown in the diagram, two other key components of a deployed Log are:

 - A collection of front-end web servers that provide HTTPS termination and
   load balancing across the Log server instances.
 - A cluster of [`etcd`](https://coreos.com/etcd/) instances that
   provide data synchronization and replication services for the Log server
   instances.

Both of these are standard components that are not specific to Certificate
Transparency, and so will only be covered briefly.

Finally, an optional (but highly recommended) component for a deployed Log is
some kind of monitoring for the operational status of the Log components.


Manual Setup
============

 - [Required Configuration](#required-configuration)
    - [Private Key Generation](#private-key-generation)
    - [CA Certificates](#ca-certificates)
 - [Optional Configuration](#optional-configuration)
 - [etcd Setup](#etcd-setup)
 - [Monitoring Setup](#monitoring-setup)
    - [GCM](#gcm)
    - [Prometheus](#prometheus)
 - [Front-End Setup](#front-end-setup)
 - [Standalone Setup](#standalone-setup)

Required Configuration
----------------------

The `ct-server` binary (from `cpp/server/`) is the core of the running CT Log
system.  Multiple distributed instances of `ct-server` should be run in
parallel to allow scaling and to ensure resilience:

 - Running multiple `ct-server` instances allows the Log to scale with traffic
   levels, by adjusting the number of instances.
 - Running `ct-server` instances in distinct locations reduces the chance of a
   single external event affecting all instances simultaneously.  (In terms of
   cloud computing providers, this means that instances should be run in
   different zones/regions/availability zones.)


Each `ct-server` instance needs to be configured with information about how it
should run and its other dependencies.  The most important configuration options
are:

 - `--key=<pemfile>` specifies the private key that the Log will use to perform
   cryptographic signing operations.  This key should not be password
   protected, but needs to be [kept carefully](Operation.md#key-management)
   to prevent Log failure.  See [below](#private-key-generation) for
   tips on how to generate a private key.
 - `--trusted_cert_file=<pemfile>` specifies the set of CA certificates that
   the Log accepts as trust roots for logged certificates.  See
   [below](#ca-certificates) for hints on possible ways to build this set.
 - `--leveldb_db=<file>.ldb` specifies the
   [LevelDB](https://github.com/google/leveldb) storage directory used to
   store the certificate data for the Log.  This needs to be stored on a
   persistent disk, and needs to be in a separate location for each
   `ct-server` instance.
 - `--etcd_servers=<host>:<port>,<host>:<port>,...` specifies the set of `etcd`
   servers that should be used for data synchronization and replication.  See
   [below](#etcd-setup) for information about `etcd` setup.

Other configuration options that need to be set to non-default values are:

 - `--server=<hostname>` identifies the local machine; this is used to
   distinguish different clustered Log instances when synchronizing, so needs
   to be distinct and resolvable/routable for each `ct-server` instance
   (i.e. cannot be `localhost`).
 - `--port=<port>` specifies the port that `ct-server` serves HTTP on; for a
   normal configuration (behind a reverse-proxy) this should be set to the
   standard web port (80).

### Private Key Generation

The [OpenSSL](https://www.openssl.org/) command line can be used to
[generate](https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations#Generating_EC_Keys_and_Parameters)
a suitable private key (and note that the
[build process](../README.md#building-the-code) generates an `openssl` binary
in `./install/bin`):

```console
% openssl ecparam -name prime256v1 > privkey.pem # generate parameters file
% openssl ecparam -in privkey.pem -genkey -noout >> privkey.pem # generate and append private key
% openssl ec -in privkey.pem -noout -text # check key is readable
% openssl ec -in privkey.pem -pubout -out pubkey.pem # generate corresponding public key
```

The private key must either be for elliptic curves using NIST P-256 (as shown
here), or for RSA signatures with SHA-256 and a 2048 bit (or larger) key
([RFC 6962 s2.1.4](https://tools.ietf.org/html/rfc6962#section-2.1.4)).

### CA Certificates

Each Log must decide on its own policy about which CA's certificates are to be
included in the Log; this section therefore just provides an *example* of the
process of configuring this set for the CT Log software.

On a Debian-based system, the `ca-certificates` package includes a collection
of CA certificates under `/etc/ssl/certs/`.  A set of certificates suitable
for feeding to `ct-server` can thus be produced with:

```console
% sudo apt-get install -qy ca-certificates
% sudo update-ca-certificates
% cat /etc/ssl/certs/* > ca-roots.pem
```

Optional Configuration
----------------------

The `ct-server` binary has many other command-line flags that alter its
operation; the most important are described below.

 - Logging Controls:
   - `-log_dir=<dir>` indicates where logging output from the Log will be placed.
   - `--v=<num>` controls logging level (higher number generates more output).
 - Monitoring configuration:
   - `--monitoring=<prometheus|gcm>` indicates which monitoring framework to
     work with, defaulting to [Prometheus](https://prometheus.io/) (which is
     pull-based); see [below](#monitoring).
 - Performance tuning:
   - `--tree_signing_frequency_seconds=<secs>` indicates how often a new STH
     should be generated; this should be set much lower than the maximum merge
     delay (MMD) you expect to commit to.
   - `--guard_window_seconds=<secs>` indicates how long to hold off before
     sequencing new entries for the log.
   - `--etcd_delete_concurrency=<num>` indicates how many `etcd` entries can be
     deleted simultaneously.
   - `--num_http_server_threads=<num>` indicates how many threads are used to
     service incoming HTTP requests.


etcd Setup
----------

The open-source CT Log relies on the presence of an
[`etcd`](https://coreos.com/etcd/) cluster to provide data synchronization and
replication facilities.   For resilience, the `etcd` cluster for a CT Log should have
multiple `etcd` instances, but does not need large numbers of instances (and
in fact large numbers of `etcd` instances will slow down replication).  Note
that the number of `etcd` instances does **not** need to be correlated with the
number of CT Log server instances.

The
[CoreOS `etcd` documentation](https://coreos.com/etcd/docs/latest/clustering.html)
covers the process of setting up this `etcd` cluster, but note that the
cluster must be seeded with some initial contents before the CT Log software
can use it (via the `--etcd_servers` command line flag).

The initial `etcd` contents are seeded by running a (one-off) command,
`prepare_etcd.sh` (from the [`cpp/tools`](cpp/tools/prepare_etcd.sh)
directory).  The arguments for this command are an `etcd` host and port, and
the [private key file](#private-key-generation) for the Log; the latter is
used when signing an initial signed tree head (STH).

For example:

```console
% cd cpp/tools
% etcdctl ls --recursive  # no contents yet
% ./prepare_etcd.sh ${ETCD_HOST} ${ETCD_PORT} privkey.pem
# May need to wait for timeout after population...
% ./etcdctl ls --recursive
/root
/root/entries
/root/nodes
/root/serving_sth
/root/cluster_config
/root/sequence_mapping
/election
```

Monitoring
----------

The CT Log server includes support for two monitoring systems:

 - [Google Cloud Monitoring](https://cloud.google.com/monitoring/) provides a
   push-based system (where the CT Log regularly pushes information/statistics
   to the monitoring system).
 - [Prometheus](https://prometheus.io/) (the default) is a pull-based system:
   the Prometheus system regularly polls the monitored system for
   information/statistics.

### GCM

Support for Google Cloud Monitoring (GCM) is enabled by setting the
`--monitoring=gcm` flag on the command line; when this is enabled,
`ct-server` will push metrics to GCM.

TODO: describe how to configure this


### Prometheus

Prometheus support is enabled by setting the `--monitoring=prometheus` flag on
the command line; when this is enabled, `ct-server` will export metrics at
`${CT_LOG_URL}/metrics` and Prometheus should be configured to scrape this
page (and similar pages exported by `etcd`).

Prometheus configuration is covered in the
[Prometheus documentation](https://prometheus.io/docs/operating/configuration/).


Front-End Setup
---------------

As the web-server that is built into the `ct-server` binary only has limited
functionality, it is normal to set up the overall CT Log system with a set of
front-end web servers that act as
[reverse proxies](https://en.wikipedia.org/wiki/Reverse_proxy) and load
balancers.  In particular, the CT Log binary does not support HTTPS so the
front-end server acts as a
[TLS termination proxy](https://en.wikipedia.org/wiki/TLS_termination_proxy).

Setup and configuration of these reverse-proxy instances is beyond the scope of
this document, but note that cloud environments often provide this functionality
(e.g. [Google Cloud Platform](https://cloud.google.com/compute/docs/load-balancing/http/),
[Amazon EC2](http://aws.amazon.com/documentation/elastic-load-balancing/)).


Standalone Setup
----------------

It can be helpful to run a CT Log instance locally, for experimentation and to
troubleshoot any problems with the binaries and configuration.  This section
collates the steps involved.

First, create a private key `privkey.pem` (with corresponding public key
`pubkey.pem`) and CA certificates file `ca-roots.pem` as
[described](#private-key-generation) [above](#ca-certificates).

Next, set up a single, local `etcd` instance and populate as [above](#etcd-setup):

```console
% etcd > etcd.out 2>&1 &  # default port 2379
% cpp/tools/prepare_etcd.sh localhost 2379 privkey.pem
... # and wait...
% etcdctl get /root/serving_sth  # check STH is populated
CAASIgogjdFMhilPo5O5inGTLeQV8sOSOVYmjKIPnwJD2Mhh0dkYs/Kikc4qIAAqIOOwxEKY/BwUmvv0yJlvuSQnrkHkZJuTTKSVmRt4UrhVMk0IBBADGkcwRQIhAITYZ8KTbGktnvxA+i44w5SkoiUSGQB0u/e2reQsZG7YAiBl9la11f2ifs6h2/mmJ6JLLJZlhCM5E1311YOgZjo8Xg=
```

The default configuration for the set of CT Log instances requires a minimum
of 2 serving nodes, so next start two `ct-server` binaries. Note that each of
them requires a separate LevelDB storage directory and a separate port.

```console
% CT_LOG_OPTS="--key=privkey.pem --trusted_cert_file=ca-roots.pem --etcd_servers=localhost:2379 -tree_signing_frequency_seconds=30 --logtostderr"
% cpp/server/ct-server ${CT_LOG_OPTS} --leveldb_db=cert-dbA.ldb --port=6962 > ct-logA.out 2>&1 &
% cpp/server/ct-server ${CT_LOG_OPTS} --leveldb_db=cert-dbB.ldb --port=6963 > ct-logB.out 2>&1 &
```

At this point, both CT Log instances should come up and it should be possible to
[check basic operation](#checking-basic-operation), with `CT_LOG_URL` set to either
`http://localhost:6962` or `http://localhost:6963`.

Alternatively, it's possible to change the [Log configuration](../proto/ct.proto) so that only a
single log instance is required:

```console
% echo "minimum_serving_nodes: 1" > /tmp/cluster_config
% cpp/tools/ct-clustertool set_config --etcd_servers=localhost:2379 --cluster_config=/tmp/cluster_config
... # and wait...
I0629 13:03:40.500687 26392 clustertool_main.cc:128] Using config:
minimum_serving_nodes: 1
...
% cpp/server/ct-server ${CT_LOG_OPTS} --leveldb_db=cert-db.ldb --port=6962 > ct-log.out 2>&1 &
```


Docker Setup
============

This section describes how to use Docker images to simplify the process of
deployment.  The underlying steps are effectively the same as for the
[manual](#manual-setup) case, but are scripted via the Docker tools and image
configuration files.

 - [Image Creation](#image-creation)
 - [Google Cloud Platform Deployment](#google-cloud-platform-deployment)
    - [Populating the Google Container Registry](#populating-the-google-container-registry)
    - [Configuring the Log](#configuring-the-log)
    - [Starting the Log](#starting-the-log)
    - [Next Steps](#next-steps)
    - [Troubleshooting](#troubleshooting)
    - [Updating Log Software](#updating-log-software)
    - [Stopping the Log](#stopping-the-log)


Image Creation
--------------

In addition to the [dependencies](../README.md#build-dependencies) needed to
build the CT Log code, the Docker client and server binaries must also be
[installed](https://docs.docker.com/engine/installation/).

Assuming that the CT Log code is
[already built](../README.md#build-quick-start), the following commands create a
collection of Docker images:

```bash
% PROJECT=ct-log  # for GCP, set this to GCP project ID
% TAG=test
% docker build -f Dockerfile -t ${PROJECT}/ct-log:${TAG} .
% docker build -f Dockerfile-ct-mirror -t ${PROJECT}/ct-mirror:${TAG} .
% docker build -f cloud/etcd/Dockerfile -t ${PROJECT}/etcd:${TAG} .
% docker build -f cloud/prometheus/Dockerfile -t ${PROJECT}/prometheus:${TAG} .
% docker images
REPOSITORY          TAG                 IMAGE ID            CREATED              VIRTUAL SIZE
ct-log/prometheus   test                223ba3c3a5ce        21 seconds ago       58.51 MB
ct-log/etcd         test                a6159881983f        47 seconds ago       187.3 MB
ct-log/ct-log       test                884a29089370        About a minute ago   280.5 MB
ct-log/ct-mirror    test                3e17f0f22c00        About a minute ago    279 MB
...
```

The `ct-mirror` image is only needed to run a [mirror log](MirrorLog.md); the
`prometheus` image is only needed if Prometheus is used instead of GCM for
monitoring.

**WARNING**: This process will generate a CT Log Docker image that contains the
**test** [private key](../test/testdata/ct-server-key.pem).  You must replace
this with a secure, unique, private key before becoming a public Log.


Google Cloud Platform Deployment
--------------------------------

The Docker images built [above](#image-creation) can be deployed using the
[Google Cloud Platform](https://cloud.google.com).  First, perform one-time
setup for the cloud platform:

 - Create a Google Cloud Platform account and configure billing settings.
 - [Install](https://cloud.google.com/sdk/downloads) the Cloud SDK tools.
 - Run `gcloud init` to
   [initialize the Cloud SDK](https://cloud.google.com/sdk/docs/initializing)
   settings.
 - Log in with `gcloud auth login`

Next, perform project setup:

 - Create a new project in the Google Compute Engine
   [console](https://console.developers.google.com), and store the Project ID
   (not Project Name) in the `PROJECT` environment variable for future steps.

   ```bash
   % export PROJECT="your_project_id"
   ```
 - Enable the following APIs for the new project (under the `APIs & Auth > APIs` tab):
    - Google Cloud APIs > Compute Engine API
    - Google Cloud APIs > Compute Engine Instance Groups API
    - Google Cloud APIs > Cloud Monitoring API (assuming GCM is used for monitoring)
 - Set the current project for the `gcloud` command line tools:

   ```bash
   gcloud config set project ${PROJECT}
   ```

### Populating the Google Container Registry

For each software release:
 - Tag the Docker images created above with a tag that includes a ``gcr.io`` hostname
   and a
   [private registry name](https://cloud.google.com/container-registry/docs/pushing),
   for example:

   ```console
   % docker tag ${PROJECT}/ct-log:${TAG}     gcr.io/${PROJECT}/ct-log:${TAG}
   % docker tag ${PROJECT}/ct-mirror:${TAG}  gcr.io/${PROJECT}/ct-mirror:${TAG}
   % docker tag ${PROJECT}/etcd:${TAG}       gcr.io/${PROJECT}/etcd:${TAG}
   % docker tag ${PROJECT}/prometheus:${TAG} gcr.io/${PROJECT}/prometheus:${TAG}
   % docker images gcr.io/${PROJECT}/*
   REPOSITORY                 TAG                 IMAGE ID            CREATED              VIRTUAL SIZE
   gcr.io/ct-log/prometheus   test                223ba3c3a5ce        About a minute ago   58.51 MB
   gcr.io/ct-log/etcd         test                a6159881983f        2 minutes ago        187.3 MB
   gcr.io/ct-log/ct-log       test                884a29089370        3 minutes ago        280.5 MB
   gcr.io/ct-log/ct-mirror    test                3e17f0f22c00        3 minutes ago        279 MB
   ...
   ```
 - Push the Docker images created above to the GCP
   [container registry](https://cloud.google.com/container-registry/) as private
   images by running the following commands.

   ```bash
   % gcloud docker push gcr.io/${PROJECT}/ct-log:${TAG}
   % gcloud docker push gcr.io/${PROJECT}/ct-mirror:${TAG}
   % gcloud docker push gcr.io/${PROJECT}/etcd:${TAG}
   % gcloud docker push gcr.io/${PROJECT}/prometheus:${TAG}
   % gcloud docker search gcr.io/${PROJECT}
   NAME                         DESCRIPTION   STARS     OFFICIAL   AUTOMATED
   ct-log-docs-test/ct-log                    0
   ct-log-docs-test/ct-mirror                 0
   ct-log-docs-test/etcd                      0
   ct-log-docs-test/prometheus                0
   ```

### Configuring the Log

The Docker images created in an [earlier step](#image-creation) still rely on
a number of configuration values that describe the run-time environment.
These values should be encoded as a set of exported environment variables in a
shell script, in the same form as the sample `cloud/google/configs/<name>.sh`
files.

The values that must be provided are:

 - `INSTANCE_TYPE`: set to `"log"` for a normal CT Log, or `"mirror"` for a
   [mirror log](MirrorLog.md).  A mirror must also have set:
    - `MIRROR_TARGET_URL`: URL for the Log instance to be mirrored
    - `MIRROR_TARGET_PUBLIC_KEY`: filename for a PEM file holding the public key
      for the Log being mirrored.
 - `PROJECT`: set to your GCP project ID.
 - `CLUSTER`: set to a name for the Log cluster, and used as a prefix for
   resources (machines, disks) used by the Log.
 - `MONITORING`: `"gcm"` or `"prometheus"`
 - `REGION`: set to the
   [region](https://cloud.google.com/compute/docs/regions-zones/regions-zones)
   that the Log will run in, e.g. `"us-central1"`.
 - `ZONES`: space-separated list of the
   [zones](https://cloud.google.com/compute/docs/regions-zones/regions-zones) to
   run instances in, e.g. `"b c f"`

Other values only need to be set if the default value is not appropriate:

 - `LOG_NUM_REPLICAS_PER_ZONE` or `MIRROR_NUM_REPLICAS_PER_ZONE` (default 2)
 - `LOG_DISK_SIZE` or `MIRROR_DISK_SIZE` (default 200GB)
 - `LOG_MACHINE_TYPE` or `MIRROR_MACHINE_TYPE` (default `n1-highmem2`)


### Starting the Log

The Log can now be started with the following commands (which will take some
time to run).

```console
% ssh-add -t 600 ${HOME}/.ssh/google_compute_engine  # Optional, stops prompts
% cloud/google/create_new_cluster.sh gcp-config.sh
...
External IPs:
NAME    REGION IP_ADDRESS    IP_PROTOCOL TARGET
log-fwd        130.211.26.21 TCP         log-lb-http-proxy
=============================================================
```

This script includes load balancing setup, and at the end of the process the
script will show the external IP address that can be used to access the log.
At this point, basic operation of the Log can be
[checked](#checking-basic-operation) with `CT_LOG_URL` set to this external IP
for the Log.

#### Prometheus SSH Tunnel

If you use Prometheus for monitoring, you can optionally create an SSH tunnel
to allow local viewing of metrics by running

```console
gcloud compute ssh ${CLUSTER}-prometheus-${ZONE}-1 --zone ${REGION}-${ZONE} --ssh-flag="-L 9092:localhost:9090"
```

This forwards local port 9092 to port 9090 (the Prometheus
[server port](https://github.com/prometheus/prometheus/wiki/Default-port-allocations))
on the virtual machine so that [http://localhost:9092](http://localhost:9092)
allows interaction with Prometheus.


### Next Steps

The steps so far have created a bare bones distributed Log that is accessible at
a public IP address.  To make this Log suitable for public consumption, the
following additional steps are recommended:

 - Set up a [DNS domain](https://cloud.google.com/dns/quickstart) for the Log.
 - Set up
   [HTTPS support](https://cloud.google.com/compute/docs/load-balancing/http/ssl-certificates#gettingakeyandcertificate)
   for the Log (using a new private key, distinct from the Log's
   [private key](#private-key-generation)).
 - (If GCM monitoring is used) Set up a dashboard for the Log in
   [GCM](https://app.google.stackdriver.com/), monitoring and alerting on
   information of interest.  For example:
    - Dashboards > Create
    - Add Chart and select:
      - Resource Type: Custom Metrics
      - Metric: `ct/total_http_server_requests`

Information about ongoing operation of a Log is covered in a [separate document](Operation.md).

### Troubleshooting

If the Log does not launch successfully:

 - Check that the expected set of virtual machines have launched from the
   Compute Engine console.
 - Check that the Docker containers are running, by `ssh`-ing into the VM
   and running `sudo docker ps -a`
     - If the containers failed to load, check `/var/log/kubelet.log` for
       relevant messages.
 - Check the container logs (from the VM) with `sudo docker logs
   <container-id>`.

### Updating Log Software

If new versions of source code need to be deployed, repeat the appropriate steps
from above to make an updated Docker image available to GCP:

 - rebuild the code (e.g. `make -C certificate-transparency`)
 - re-generate the appropriate Docker image (e.g.
   `docker build -f Dockerfile -t gcr.io/${PROJECT}/ct-log:${TAG} .`)
 - push the Docker image to **gcr.io** (e.g.
   `gcloud docker push gcr.io/${PROJECT}/ct-log:${TAG}`)

The running instances can then be updated with the appropriate
`cloud/google/update_<type>.sh` script using the Log configuration file
[created previously](#configuring-the-log), for example:
```bash
cloud/google/update_log.sh gcp-config.sh
 ```

This will restart the containers with the new image for the binary, but as the
Log database is set up on a persistent disk, there should be no data loss during
the upgrade.

For the Log component (i.e. for the `update_log.sh` or `update_mirror.sh`
scripts), this restart process proceeds incrementally, waiting for each instance
to update and become ready before moving on to the next instance.  This helps
to ensure a safer upgrade &ndash; only 1/N of the Log's capacity is out of action
during the upgrade, and a catastrophic failure will hopefully be spotted on the
first instance upgrade.  However, it does mean that Logs that contain a large
number of certificates (e.g. millions) may take while to update.


### Stopping the Log

**Stopping the Log will lose the Log data**, so a Log that needs to remain
operational/trusted must be kept running.

However, a test Log can be stopped with the following commands:

```console
% cloud/google/stop_prometheus.sh gcp-config.sh
% cloud/google/stop_log.sh gcp-config.sh
% cloud/google/stop_etcd.sh gcp-config.sh
```


Checking Basic Operation
========================

Once a Log is up and running a quick
[smoke test](https://en.wikipedia.org/wiki/Smoke_testing_(software)) helps to
confirm basic operation.  Throughout this section `CT_LOG_URL` is assumed to
hold the base URL for accessing the Log, and `pubkey.pem` is assumed to hold
the public key for the Log.

 - [Signed Tree Head (STH) Retrieval](#signed-tree-head-sth-retrieval)
 - [Certificate Upload](#certificate-upload)
 - [Monitoring Check](#monitoring-check)
 - [Validity Check](#validity-check)


Signed Tree Head (STH) Retrieval
--------------------------------

As an initial test for an unpopulated Log, the `${CT_LOG_URL}/ct/v1/get-sth`
URL should return a JSON object indicating a tree size of 0:

```console
% curl ${CT_LOG_URL}/ct/v1/get-sth
{ "tree_size": 0, "timestamp": 1464083694802, "sha256_root_hash": "47DEQpj8HBSa+\/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "tree_head_signature": "BAMARzBFAiEArVdWngQ1apI0F+XDUphNMcN5t6hKjcLpik0qLpN8j7MCIG6zJhR10y0hB4MzTOufqXI4Lr33HV6RnbcVcyhfaKsU" }
```

Certificate Upload
------------------

The next thing to confirm is that the Log accepts certificates.  To check
this, use the CT client tool to upload an arbitrary certificate.

```console
% # Any sample cert will do, pick one from Google
% openssl s_client -connect www.google.com:443 -showcerts < /dev/null > sample-cert-chain.pem
% CT_CLIENT_OPTS="--ct_server=${CT_LOG_URL} --ct_server_public_key=pubkey.pem"
% cpp/client/ct upload ${CT_CLIENT_OPTS} --ct_server_submission=sample-cert-chain.pem --ct_server_response_out=sct.out
% hexdump sct.out  # Signed Certificate Timestamp in binary format
0000000 8d00 4cd1 2986 a34f b993 718a 2d93 15e4
<snip>
0000070 87c8 ea23 e794
0000076
```

This certificate will not appear in the Log immediately, but after waiting
longer than the Log's configured `--tree_signing_frequency_seconds` (plus the
`--guard_window_seconds`) a new tree should be visible:

```bash
% curl ${CT_LOG_URL}/ct/v1/get-sth
{ "tree_size": 1, "timestamp": 1464086031550, "sha256_root_hash": "8NtHiU058EnwRXa+f\/tawi3HmKal0vSHnYshyMLnrSk=", "tree_head_signature": "BAMARzBFAiAjSpXrwejCHjfbFxwZMU2+pSBFYPE8KUXlgZrRC\/SLvQIhAPgSoANCdBrNExCEGq\/sL\/k4ylabVvYXtciYZJUNCrlJ" }
```


Monitoring Check
----------------

If the Log is configured to export
[statistics for the Prometheus](#prometheus) monitoring system, then we can
also check the state of the Log via the same methods that
[Prometheus](#prometheus) would use.  The `${CT_LOG_URL}/metrics` page shows
the available statistics; for example, after a single certificate upload the
`serving_tree_size` statistic will show a value of 1:

```
name: "serving_tree_size" help: "Size of the current serving STH" type: GAUGE
metric { gauge { value: 1 } timestamp_ms: 1464086259039 }
```


Validity Check
--------------

Finally, we want to check the validity of the SCT that was returned when we
[uploaded a certificate](#certificate-upload).

 - First, wrap up the uploaded certificate chain and corresponding SCT together:

   ```
   % cpp/client/ct wrap ${CT_CLIENT_OPTS} --sct_in=sct.out --certificate_chain_in=sample-cert-chain.pem --ssl_client_ct_data_out=sample.ctdata
   ```
 - Then confirm that the log has the uploaded certificate, by retrieving a
   [proof by leaf hash](https://tools.ietf.org/html/rfc6962#section-4.5):

   ```
   % cpp/client/ct audit ${CT_CLIENT_OPTS} --ssl_client_ct_data_in=sample.ctdata --logtostderr
   ...
   I0609 16:46:01.964999  4812 ct.cc:643] Received proof:
   version: V1
   id {
     key_id: "\244\271\t\220\264\030X\024\207\273\023\242\314gp\n<5\230\004\371\033\337\270\343w\315\016\310\r\334\020"
   }
   tree_size: 19948496
   timestamp: 1465484237467
   leaf_index: 17761460
   path_node: "\ru\316\371C\025,\256\360\242<U\344<D\367\341L\213\242:\317\220y\241\211\264\217s)\214\034"
   ...
   tree_head_signature {
     hash_algorithm: SHA256
     sig_algorithm: ECDSA
     signature: "0D\002 \005\262\246]\357D\207f%\247HF\205\010\010\233\206\350J\237\t\223f\246\226\251\317_i\337\237\010\002 Pd\354\255\315\225X\237\272dv\336w\3720\035\027\361\006H\347\222\222\320\t\t\370F\247|\372\222"
   }
   I0609 16:46:01.965592  4812 ct.cc:653] Proof verified.
   ```
