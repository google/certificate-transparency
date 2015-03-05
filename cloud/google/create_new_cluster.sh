#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

function WaitForEtcd() {
 gcloud compute ssh k8s-${CLUSTER}-node-1 --command "\
   until curl -s -L -m 10 ${ETCD}/v2/keys/ > /dev/null; do \
     echo -n .; \
     sleep 1; \
   done"
}

function PopulateEtcd() {
  export ETCD=$(gcloud preview container services list | \
      grep etcd-service | awk '{print $4":"$5}')
  export ETCD_HOST=${ETCD%%:*}
  export ETCD_PORT=${ETCD##*:}
  export PUT="curl -s -L -X PUT"
  gcloud compute ssh k8s-${CLUSTER}-node-1 --command "\
    ${PUT} ${ETCD}/v2/keys/root/serving_sth && \
    ${PUT} ${ETCD}/v2/keys/root/cluster_config && \
    ${PUT} ${ETCD}/v2/keys/root/sequenced/ -d dir=true && \
    ${PUT} ${ETCD}/v2/keys/root/unsequenced/ -d dir=true && \
    ${PUT} ${ETCD}/v2/keys/root/nodes/ -d dir=true"
  pushd ${DIR}/../../cpp
  make -j24 tools/ct-clustertool
  popd
  gcloud compute copy-files ${DIR}/../../cpp/tools/ct-clustertool \
    k8s-${CLUSTER}-node-1:.
  gcloud compute ssh k8s-${CLUSTER}-node-1 --command "\
    sudo docker run localhost:5000/alcutter/super_duper:test \
      /usr/local/bin/ct-clustertool initlog \
      --key=/usr/local/etc/ct-server-key.pem \
      --etcd_host=${ETCD_HOST} \
      --etcd_port=${ETCD_PORT} \
      --logtostderr --v=2"
}

export PROJECT=${PROJECT:-your-gce-project}
export CLUSTER=${CLUSTER:-${USER}-superduper-test}
export ZONE=${ZONE:-europe-west1-b}
export NUM_ETCD_REPLICAS=3
export NUM_LOGSERVER_REPLICAS=3
export TOTAL_REPLICAS=$(expr ${NUM_ETCD_REPLICAS} + \
    ${NUM_LOGSERVER_REPLICAS})
export MACHINE_TYPE=n1-standard-2

echo "============================================================="
echo "Creating new GCE/GKE cluster with settings:"
echo "PROJECT:   ${PROJECT}   <-- ensure this already exists!"
echo "CLUSTER:   ${CLUSTER}"
echo "ZONE:      ${ZONE}"
echo "Num etcd:  ${NUM_ETCD_REPLICAS}"
echo "Num logs:  ${NUM_LOGSERVER_REPLICAS}"
echo "============================================================="

# Set gcloud defaults:
gcloud config set project ${PROJECT}
gcloud config set compute/zone ${ZONE}
gcloud config set container/cluster ${CLUSTER}

# Make sure we have the "preview" commands:
gcloud components update preview

echo "============================================================="
echo "Creating cluster..."
#gcloud preview container clusters create ${CLUSTER} \
#    --zone=${ZONE} \
#    --num-nodes=${TOTAL_REPLICAS} \
#    --machine-type=${MACHINE_TYPE}

echo "============================================================="
echo "Creating etcd instances..."
${DIR}/start_etcd.sh

export ETCD=$(gcloud preview container services list | \
    grep etcd-service | awk '{print $4":"$5}')
export ETCD_HOST=${ETCD%%:*}
export ETCD_PORT=${ETCD##*:}
echo "============================================================="
echo "Etcd service will be at ${ETCD}"

echo "============================================================="
echo "Waiting for etcd to start..."
WaitForEtcd

echo "============================================================="
echo "Populating etcd with default entries..."
PopulateEtcd

echo "============================================================="
echo "Creating superduper instances..."
${DIR}/start_log.sh

echo "============================================================="
echo "Starting prometheus..."
${DIR}/start_prometheus.sh
${DIR}/update_prometheus_config.sh

echo "============================================================="
echo "Creating forwarding rules..."
gcloud compute firewall-rules create log-node-80 \
    --allow tcp:80 \
    --target-tags k8s-${CLUSTER}-node

echo
echo "============================================================="
echo "Services:"
${CLOUD} container services list
echo "============================================================="
echo "Pods:"
${CLOUD} container pods list
echo "============================================================="
echo "External IPs:"
${CLOUD} compute forwarding-rules list
echo "============================================================="

echo "Job done!"
