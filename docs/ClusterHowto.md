# HOWTO run a clustered CT log server

## Intro
This HOWTO is intended to get you started running a clustered CT "Super Duper" log server.
The scripts in the rep referenced below are targetted at running a log cluster in [Google Compute Engine](https://cloud.google.com)
, but since it's all based around [Docker](https://docker.io) images it shouldn't be too hard to use the scripts as a reference for getting a log running on any other infrastructure where you can easily run Docker containers.


## Prerequisites
You should have:
* Installed the dependencies listed in the top-level [README.md](https://github.com/google/certificate-transparency/README.md) file,
* Installed the Docker utilities (and started the docker daemon if it's not already running)
* Signed up for a [Google Cloud](https://cloud.google.com) account _[only required if you're intending to use GCE, of course]_

### Dependencies for Debian-based distros
Assuming you're happy to use the stock versions of dependencies, Debian-based distros (including Ubuntoo etc.) have many of them pre-packaged which will make your life easier, you can install them using the following command:
```bash
sudo apt-get update
sudo apt-get -V -y install \
       pkg-config \
       clang \
       openssl \
       libssl-dev \
       cmake \
       google-mock \
       protobuf-compiler \
       libprotobuf-dev \
       libgflags-dev \
       libgoogle-glog-dev \
       libsqlite3-dev \
       libjson-c-dev \
       libevent-2.0-5 \
       libevent-dev \
       libldns-dev \
       wget \
       curl
# Install latest version of Docker from docker.io (the system version is very old):
wget -qO- https://get.docker.com/ | sh
# Install latest version of Cloud SDK from Google
curl https://sdk.cloud.google.com | bash
```

## Setup for Google Compute Engine
1. First, create a new project on your GCE [console](https://console.developers.google.com).
1. Put the ID of the project you created into the PROJECT environment variable:
   ```bash
   export PROJECT="your_project_id_here"
   ```
   
1. Enable the following APIs for your new project (look under the `APIs & Auth > APIs` tab in your project's area of your GCE console):
   * Compute Engine API
   
1. If you've not done it before, log in with gcloud:
   ```bash
   gcloud auth login
   gcloud config set project ${PROJECT}
   ```
   
1. We're going to store our Docker images inside Google Compute Storage, so we need to create a storage bucket and set up a credentials file:
   ```bash
   export GCS_BUCKET=${PROJECT}_ctlog_images
   gsutil mb gs://${GCS_BUCKET}
   echo -e \
       GCP_OAUTH2_REFRESH_TOKEN=$(gcloud auth print-refresh-token)\\n\
       GCS_BUCKET=${GCS_BUCKET} > registry-params.env
   ```
   
1. Start a local Docker registry (we'll use that to push the docker images to GCS):
   ```bash
   sudo docker run -d --env-file=registry-params.env \
       -p 5000:5000 google/docker-registry
   ```

## Fetching and building
   ```bash
   export CXX=clang++
   git clone https://github.com/google/certificate-transparency.git
   cd certificate-transparency
   make -C cpp -j24 proto/libproto.a server/ct-server
   make docker
   docker push localhost:5000/certificate_transparency/super_duper:test
   docker push localhost:5000/certificate_transparency/etcd:test
   docker push localhost:5000/certificate_transparency/prometheus:test
   ```

## Starting the cluster on Google Compute Engine
1. Edit the settings in the `cloud/google/config.sh` file
1. Run `cloud/google/create_new_cluster.sh`
1. Make a cup of tea while you wait for the jobs to come up
1. [optional] Create an SSH tunnel for viewing the metrics on Prometheus:
   ```bash
   gcloud compute ssh ${USER}-ctlog-prometheus-1 --ssh-flag="-L 9092:localhost:9090"
   ```
   
   Pointing your browser at [http://localhost:9092](http://localhost:9092) should let you add graphs/inspect the metrics gathered by prometheus.


## Stopping the cluster on Google Compute Engine
**WARNING: YOU WILL LOSE THE LOG DATA!**

Run the following commands:
   ```bash
   cloud/google/stop_prometheus.sh
   cloud/google/stop_log.sh
   cloud/google/stop_etcd.sh
   ```

## Updating the log server binaries
If you're like to update the running CT Log Server code, then it's just a matter of building new Docker images, pushing them up to GCS, and restarting the containers.
1. Make whatever changes you wish to the code base, then rebuild and create new docker image:
   ```bash
   make -C cpp -j24 proto/libproto.a server/ct-server
   make docker
   ```
   
1. push the image into GCS:
   ```bash
   docker push localhost:5000/certificate_transparency/super_duper:test
   ```
   
1. finally, ssh into each of the log machines, they'll be called `${USER}-ctlog-log-X` (where X is a number in the range 1 to however many servers you have configured), e.g:
   ```bash
   gcloud compute ssh ${USER}-ctlog-log-1
   ...ctlog-log-1$ sudo docker pull localhost:5000/certificate_transparency/super_duper:test
   ...ctlog-log-1$ sudo docker ps
   # find the container ID of the log container (since you've already updated the docker image tag,
   # it's likely to be the container whose IMAGE name is just a hex number rather than the 
   # `localhost:5000/...` style tag.) 
   ...ctlog-log-1$ sudo docker kill <your_container_id_goes_here>
   ```
   The containers should re-start with the new image and continue on their way.  Since the log DB lives on persistent disks mounted by the container images, there shouldn't be any data loss doing this.
