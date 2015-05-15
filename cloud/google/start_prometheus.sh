#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/util.sh
source ${DIR}/config.sh

set -e
GCLOUD="gcloud"

Header "Creating prometheus persistent disks..."
for i in ${PROMETHEUS_DISKS[@]}; do
  echo "Creating disk ${i}..."
  ${GCLOUD} compute disks create -q ${i} \
      --size=${PROMETHEUS_DISK_SIZE} &
done
wait

for i in ${PROMETHEUS_DISKS[@]}; do
  echo "Waiting for disk ${i}..."
  WaitForStatus disks ${i} READY &
done
wait

MANIFEST=/tmp/prometheus_container.yaml
sed --e "s^@@GCS_BUCKET@@^${GCS_BUCKET}^" \
    < ${DIR}/prometheus_container.yaml > ${MANIFEST}


Header "Creating prometheus instances..."
for i in `seq ${PROMETHEUS_NUM_REPLICAS}`; do
  echo "Creating instance ${PROMETHEUS_MACHINES[$i]}"

  ${GCLOUD} compute instances create -q ${PROMETHEUS_MACHINES[${i}]} \
      --machine-type ${PROMETHEUS_MACHINE_TYPE} \
      --image container-vm \
      --disk name=${PROMETHEUS_DISKS[${i}]},mode=rw,boot=no,auto-delete=yes \
      --tags prometheus-node \
      --metadata-from-file startup-script=${DIR}/node_init.sh \
                           google-container-manifest=${MANIFEST} &
done
wait

for i in ${PROMETHEUS_MACHINES[@]}; do
  echo "Waiting for instance ${i}..."
  WaitForStatus instances ${i} RUNNING &
done
wait


