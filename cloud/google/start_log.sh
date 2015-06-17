#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/util.sh
source ${DIR}/config.sh

set -e
GCLOUD="gcloud"

Header "Creating log persistent disks..."
for i in ${LOG_DISKS[@]}; do
  echo "Creating disk ${i}..."
  ${GCLOUD} compute disks create -q ${i} \
      --size=${LOG_DISK_SIZE} &
done
wait

for i in ${LOG_DISKS[@]}; do
  echo "Waiting for disk ${i}..."
  WaitForStatus disks ${i} READY &
done
wait

MANIFEST=/tmp/log_container.yaml

Header "Creating log instances..."
for i in `seq ${LOG_NUM_REPLICAS}`; do
  echo "Creating instance ${LOG_MACHINES[$i]}"

  sed --e "s^@@PROJECT@@^${PROJECT}^
           s^@@ETCD_HOST@@^${ETCD_MACHINES[1]}^
           s^@@ETCD_PORT@@^4001^
           s^@@CONTAINER_HOST@@^${LOG_MACHINES[$i]}^" \
          < ${DIR}/log_container.yaml  > ${MANIFEST}.${i}

  ${GCLOUD} compute instances create -q ${LOG_MACHINES[${i}]} \
      --machine-type ${LOG_MACHINE_TYPE} \
      --image container-vm \
      --disk name=${LOG_DISKS[${i}]},mode=rw,boot=no,auto-delete=yes \
      --tags log-node \
      --metadata-from-file startup-script=${DIR}/node_init.sh,google-container-manifest=${MANIFEST}.${i} &
done
wait

for i in ${LOG_MACHINES[@]}; do
  echo "Waiting for instance ${i}..."
  WaitForStatus instances ${i} RUNNING &
done
wait


