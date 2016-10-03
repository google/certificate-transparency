#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
if [ "$1" == "" ]; then
  echo "Usage: $0 <config.sh file>"
  exit 1;
fi
source ${DIR}/config.sh $1
source ${DIR}/util.sh

set -e
GCLOUD="gcloud --project ${PROJECT}"

Header "Creating prometheus persistent disks..."
for i in `seq 0 $((${PROMETHEUS_NUM_REPLICAS} - 1))`; do
  echo "Creating disk ${PROMETHEUS_DISKS[${i}]}..."
  ${GCLOUD} compute disks create -q ${PROMETHEUS_DISKS[${i}]} \
      --zone=${PROMETHEUS_ZONES[${i}]} \
      --size=${PROMETHEUS_DISK_SIZE} &
done
wait

for i in `seq 0 $((${PROMETHEUS_NUM_REPLICAS} - 1))`; do
  echo "Waiting for disk ${PROMETHEUS_DISKS[${i}]}..."
  WaitForStatus disks ${PROMETHEUS_DISKS[${i}]} ${PROMETHEUS_ZONES[${i}]} READY &
done
wait

function create_instance()
{
  echo "Creating instance ${PROMETHEUS_MACHINES[$1]}"

  MANIFEST=$(mktemp)
  sed --e "s^@@PROJECT@@^${PROJECT}^
           s^@@CONTAINER_HOST@@^${PROMETHEUS_MACHINES[$1]}^" \
      < ${DIR}/prometheus_container.yaml > ${MANIFEST}

  ${GCLOUD} compute instances create -q ${PROMETHEUS_MACHINES[$1]} \
      --zone ${PROMETHEUS_ZONES[$1]} \
      --machine-type ${PROMETHEUS_MACHINE_TYPE} \
      --image container-vm \
      --disk name=${PROMETHEUS_DISKS[$1]},mode=rw,boot=no,auto-delete=yes \
      --tags prometheus-node \
      --metadata-from-file startup-script=${DIR}/node_init.sh,google-container-manifest=${MANIFEST}

  rm "${MANIFEST}"
}

Header "Creating prometheus instances..."
for i in `seq 0 $((${PROMETHEUS_NUM_REPLICAS} - 1))`; do
  create_instance $i &
done
wait

for i in `seq 0 $((${PROMETHEUS_NUM_REPLICAS} - 1))`; do
  echo "Waiting for instance ${PROMETHEUS_MACHINES[${i}]}..."
  WaitForStatus instances ${PROMETHEUS_MACHINES[${i}]} ${PROMETHEUS_ZONES[${i}]} RUNNING &
done
wait


