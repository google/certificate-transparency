#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
GCLOUD="gcloud"

. ${DIR}/mirror-config.sh

if [ ! -x ${DIR}/../../cpp/tools/ct-clustertool ]; then
  echo "Please ensure that cpp/tools/ct-clustertool is built."
  exit 1
fi

function WaitForEtcd() {
  while true; do
    gcloud compute ssh ${ETCD_MACHINES[1]} --command "\
     until curl -s -L -m 10 localhost:4001/v2/keys/ > /dev/null; do \
       echo -n .; \
       sleep 1; \
     done" && break;
    sleep 1
    echo "Retrying..."
  done
}

function PopulateEtcd() {
  export PUT="curl -s -L -X PUT --retry 10"
  export ETCD="${ETCD_MACHINES[1]}:4001"
  gcloud compute ssh ${ETCD_MACHINES[1]} --command "\
    ${PUT} ${ETCD}/v2/keys/root/serving_sth && \
    ${PUT} ${ETCD}/v2/keys/root/cluster_config && \
    ${PUT} ${ETCD}/v2/keys/root/nodes/ -d dir=true"
  gcloud compute copy-files ${DIR}/../../cpp/tools/ct-clustertool \
    ${ETCD_MACHINES[1]}:.
}

echo "============================================================="
echo "Creating new GCE-based mirror cluster."
echo "============================================================="

# Set gcloud defaults:
${GCLOUD} config set project ${PROJECT}
${GCLOUD} config set compute/zone ${ZONE}


echo "============================================================="
echo "Creating etcd instances..."
${DIR}/start_etcd.sh ${DIR}/mirror-config.sh

WaitForEtcd

echo "============================================================="
echo "Populating etcd with default entries..."
PopulateEtcd


echo "============================================================="
echo "Creating supermirror instances..."
${DIR}/start_mirror.sh ${DIR}/mirror-config.sh

echo "============================================================="
echo "Starting prometheus..."
${DIR}/start_prometheus.sh ${DIR}/mirror-config.sh
${DIR}/update_prometheus_config.sh ${DIR}/mirror-config.sh


echo "============================================================="
echo "Creating network rules..."
gcloud compute http-health-checks create get-sth-check \
    --port 80 \
    --request-path /ct/v1/get-sth
gcloud compute firewall-rules create mirror-node-80 \
    --allow tcp:80 \
    --target-tags mirror-node
gcloud compute target-pools create mirror-pool \
    --region ${REGION} \
    --health-check get-sth-check
gcloud compute target-pools add-instances mirror-pool \
    --zone $ZONE \
    --instances ${MIRROR_MACHINES[@]}
gcloud compute forwarding-rules create mirror-fwd-rule \
    --region $REGION \
    --port-range 80 \
    --target-pool mirror-pool

echo "============================================================="
echo "External IPs:"
gcloud compute forwarding-rules list
echo "============================================================="

echo "Job done!"
