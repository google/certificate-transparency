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

function recreate_instance()
{
  echo "Deleting instance ${MIRROR_MACHINES[$1]}"
  set +e
   ${GCLOUD} compute instances delete -q ${MIRROR_MACHINES[$1]} \
      --zone ${MIRROR_ZONES[$1]} \
      --keep-disks data
  set -e

  MANIFEST=$(mktemp)
  echo "${MIRROR_META[$1]}" > ${MANIFEST}

  echo "Recreating instance ${MIRROR_MACHINES[$1]}"
  ${GCLOUD} compute instances create -q ${MIRROR_MACHINES[$1]} \
      --zone ${MIRROR_ZONES[$1]} \
      --machine-type ${MIRROR_MACHINE_TYPE} \
      --image-family=container-vm \
      --image-project=google-containers \
      --disk name=${MIRROR_DISKS[$1]},mode=rw,boot=no,auto-delete=no \
      --tags mirror-node \
      --scopes "monitoring,storage-ro,compute-ro,logging-write" \
      --metadata-from-file startup-script=${DIR}/node_init.sh,google-container-manifest=${MANIFEST}

  rm "${MANIFEST}"

  ${GCLOUD} compute instance-groups unmanaged add-instances \
      "mirror-group-${MIRROR_ZONES[$1]}" \
      --zone ${MIRROR_ZONES[$1]} \
      --instances ${MIRROR_MACHINES[$1]} &
}

Header "Recreating mirror instances..."
for i in `seq 0 $((${MIRROR_NUM_REPLICAS} - 1))`; do
  recreate_instance $i

  set +e
  echo "Waiting for instance ${MIRROR_MACHINES[${i}]}..."
  WaitForStatus instances ${MIRROR_MACHINES[${i}]} ${MIRROR_ZONES[${i}]} RUNNING
  echo "Waiting for mirror service on ${MIRROR_MACHINES[${i}]}..."
  WaitHttpStatus ${MIRROR_MACHINES[${i}]} ${MIRROR_ZONES[${i}]} /ct/v1/get-sth 200
  set -e
done
