#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/util.sh
source ${DIR}/config.sh

set -e
GCLOUD="gcloud"

Header "Creating etcd persistent disks..."
for i in ${ETCD_DISKS[@]}; do
  echo "Creating disk ${i}..."
  ${GCLOUD} compute disks create -q ${i} \
      --size=${ETCD_DISK_SIZE} &
done
wait

for i in ${ETCD_DISKS[@]}; do
  echo "Waiting for disk ${i}..."
  WaitForStatus disks ${i} READY &
done
wait

MANIFEST=/tmp/etcd_container.yaml
DISCOVERY=$(curl -s https://discovery.etcd.io/new?size=3)

echo
echo "Using Discovery URL: ${DISCOVERY}"
echo


Header "Creating etcd instances..."
for i in `seq ${ETCD_NUM_REPLICAS}`; do
  echo "Creating instance ${ETCD_MACHINES[$i]}"

  sed --e "s^@@GCS_BUCKET@@^${GCS_BUCKET}^
           s^@@DISCOVERY@@^${DISCOVERY}^
           s^@@ETCD_NAME@@^${ETCD_MACHINES[$i]}^
           s^@@CONTAINER_HOST@@^${ETCD_MACHINES[$i]}^" \
          < ${DIR}/etcd_container.yaml  > ${MANIFEST}.${i}

  ${GCLOUD} compute instances create -q ${ETCD_MACHINES[${i}]} \
      --machine-type ${ETCD_MACHINE_TYPE} \
      --image container-vm \
      --disk name=${ETCD_DISKS[${i}]},mode=rw,boot=no,auto-delete=yes \
      --tags etcd-node \
      --metadata-from-file startup-script=${DIR}/node_init.sh \
                           google-container-manifest=${MANIFEST}.${i} &
done
wait

for i in ${ETCD_MACHINES[@]}; do
  echo "Waiting for instance ${i}..."
  WaitForStatus instances ${i} RUNNING &
done
wait


