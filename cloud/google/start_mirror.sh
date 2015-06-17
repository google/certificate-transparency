#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
if [ "$1" == "" ]; then
  echo "Usage: $0 <config.sh file>"
  exit 1;
fi
source $1
source ${DIR}/util.sh

set -e
GCLOUD="gcloud"

Header "Creating mirror persistent disks..."
for i in `seq 0 $((${MIRROR_NUM_REPLICAS} - 1))`; do
  echo "Creating disk ${MIRROR_DISKS[${i}]}..."
  ${GCLOUD} compute disks create -q ${MIRROR_DISKS[${i}]} \
      --zone ${MIRROR_ZONES[${i}]} \
      --size=${MIRROR_DISK_SIZE} &
done
wait

for i in `seq 0 $((${MIRROR_NUM_REPLICAS} - 1))`; do
  echo "Waiting for disk ${MIRROR_DISKS[${i}]}..."
  WaitForStatus disks ${MIRROR_DISKS[${i}]} ${MIRROR_ZONES[${i}]} READY &
done
wait

MANIFEST=/tmp/mirror_container.yaml

Header "Creating mirror instances..."
for i in `seq 0 $((${MIRROR_NUM_REPLICAS} - 1))`; do
  echo "Creating instance ${MIRROR_MACHINES[$i]}"

  sed --e "s^@@PROJECT@@^${PROJECT}^
           s^@@ETCD_HOST@@^${ETCD_MACHINES[1]}^
           s^@@ETCD_PORT@@^4001^
           s^@@CONTAINER_HOST@@^${MIRROR_MACHINES[$i]}^
           s^@@TARGET_LOG_URL@@^${MIRROR_TARGET_URL}^
           s^@@TARGET_LOG_PUBLIC_KEY@@^${MIRROR_TARGET_PUBLIC_KEY}^" \
          < ${DIR}/mirror_container.yaml  > ${MANIFEST}.${i}

  ${GCLOUD} compute instances create -q ${MIRROR_MACHINES[${i}]} \
      --zone ${MIRROR_ZONES[${i}]} \
      --machine-type ${MIRROR_MACHINE_TYPE} \
      --image container-vm \
      --disk name=${MIRROR_DISKS[${i}]},mode=rw,boot=no,auto-delete=yes \
      --tags mirror-node \
      --metadata-from-file startup-script=${DIR}/node_init.sh,google-container-manifest=${MANIFEST}.${i} &
done
wait

for i in `seq 0 $((${MIRROR_NUM_REPLICAS} - 1))`; do
  echo "Waiting for instance ${MIRROR_MACHINES[${i}]}..."
  WaitForStatus instances ${MIRROR_MACHINES[${i}]} ${MIRROR_ZONES[${i}]} RUNNING &
done
wait


