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

Header "Creating etcd persistent disks..."
for i in `seq 0 $((${ETCD_NUM_REPLICAS} - 1))`; do
  echo "Creating disk ${ETCD_DISKS[${i}]}..."
  ${GCLOUD} compute disks create -q ${ETCD_DISKS[${i}]} \
      --zone=${ETCD_ZONES[${i}]} \
      --size=${ETCD_DISK_SIZE} &
done
wait

for i in `seq 0 $((${ETCD_NUM_REPLICAS} - 1))`; do
  echo "Waiting for disk ${ETCD_DISKS[${i}]}..."
  WaitForStatus disks ${ETCD_DISKS[${i}]} ${ETCD_ZONES[${i}]} READY &
done
wait

echo -n "Getting Discovery URL"
while [ "${DISCOVERY}" == "" ]; do
  DISCOVERY=$(curl -s https://discovery.etcd.io/new?size=${ETCD_NUM_REPLICAS})
  echo .
  sleep 1
done

echo
echo "Using Discovery URL: ${DISCOVERY}"
echo

function create_instance()
{
  echo "Creating instance ${ETCD_MACHINES[$1]}"

  MANIFEST=$(mktemp)
  sed --e "s^@@PROJECT@@^${PROJECT}^
           s^@@DISCOVERY@@^${DISCOVERY}^
           s^@@ETCD_NAME@@^${ETCD_MACHINES[$1]}^
           s^@@CONTAINER_HOST@@^${ETCD_MACHINES[$1]}^" \
          < ${DIR}/etcd_container.yaml  > ${MANIFEST}

  ${GCLOUD} compute instances create -q ${ETCD_MACHINES[$1]} \
      --zone ${ETCD_ZONES[$1]} \
      --machine-type ${ETCD_MACHINE_TYPE} \
      --image-family=container-vm \
      --image-project=google-containers \
      --disk name=${ETCD_DISKS[$1]},mode=rw,boot=no,auto-delete=yes \
      --tags etcd-node \
      --metadata-from-file startup-script=${DIR}/node_init.sh,google-container-manifest=${MANIFEST}

  rm "${MANIFEST}"
}

Header "Creating etcd instances..."
for i in `seq 0 $((${ETCD_NUM_REPLICAS} - 1))`; do
  create_instance $i &
done
wait

for i in `seq 0 $((${ETCD_NUM_REPLICAS} - 1))`; do
  echo "Waiting for instance ${ETCD_MACHINES[${i}]}..."
  WaitForStatus instances ${ETCD_MACHINES[${i}]} ${ETCD_ZONES[${i}]} RUNNING &
done
wait


