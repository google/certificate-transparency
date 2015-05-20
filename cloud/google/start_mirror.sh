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
for i in ${MIRROR_DISKS[@]}; do
  echo "Creating disk ${i}..."
  ${GCLOUD} compute disks create -q ${i} \
      --size=${MIRROR_DISK_SIZE} &
done
wait

for i in ${MIRROR_DISKS[@]}; do
  echo "Waiting for disk ${i}..."
  WaitForStatus disks ${i} READY &
done
wait

MANIFEST=/tmp/mirror_container.yaml

Header "Creating mirror instances..."
for i in `seq ${MIRROR_NUM_REPLICAS}`; do
  echo "Creating instance ${MIRROR_MACHINES[$i]}"

  sed --e "s^@@GCS_BUCKET@@^${GCS_BUCKET}^
           s^@@ETCD_HOST@@^${ETCD_MACHINES[1]}^
           s^@@ETCD_PORT@@^4001^
           s^@@CONTAINER_HOST@@^${MIRROR_MACHINES[$i]}^
           s^@@TARGET_LOG_URL@@^${MIRROR_TARGET_URL}^
           s^@@TARGET_LOG_PUBLIC_KEY@@^${MIRROR_TARGET_PUBLIC_KEY}^" \
          < ${DIR}/mirror_container.yaml  > ${MANIFEST}.${i}

  ${GCLOUD} compute instances create -q ${MIRROR_MACHINES[${i}]} \
      --machine-type ${MIRROR_MACHINE_TYPE} \
      --image container-vm \
      --disk name=${MIRROR_DISKS[${i}]},mode=rw,boot=no,auto-delete=yes \
      --tags mirror-node \
      --metadata-from-file startup-script=${DIR}/node_init.sh,google-container-manifest=${MANIFEST}.${i} &
done
wait

for i in ${MIRROR_MACHINES[@]}; do
  echo "Waiting for instance ${i}..."
  WaitForStatus instances ${i} RUNNING &
done
wait


