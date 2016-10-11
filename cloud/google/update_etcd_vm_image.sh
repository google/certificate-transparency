#!/bin/bash
#
# This script deletes & re-creates the etcd VMs, one-by-one waiting for each
# updated node to boot and become healthy before moving on to the next.
#
# It's intended to be used to update the software running on the etcd nodes,
# but can also be useful in situations where the etcd node(s) are unable to
# boot/function properly (e.g. if their root disks fill up.)
#
# The persistent disks are left intact, and are attached to the updated
# VM instances.
#
# The expected outcome from running this script is that the etcd cluster
# updates to the newest project etcd image, and the data within etcd remains
# intact.

# TODO(alcutter): Factor out common code with update_mirror_vm_image.sh script
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
if [ "$1" == "" ]; then
  echo "Usage: $0 <config.sh file>"
  exit 1;
fi
source ${DIR}/config.sh $1
source ${DIR}/util.sh

set -e
GCLOUD="gcloud --project ${PROJECT}"

Header "Recreating etcd instances..."
for i in `seq 0 $((${ETCD_NUM_REPLICAS} - 1))`; do
  echo "Deleting instance ${ETCD_MACHINES[$i]}"
  set +e
   ${GCLOUD} compute instances delete -q ${ETCD_MACHINES[${i}]} \
      --zone ${ETCD_ZONES[${i}]} \
      --keep-disks data
  set -e

  MANIFEST=$(mktemp)
  sed --e "s^@@PROJECT@@^${PROJECT}^
           s^@@DISCOVERY@@^${DISCOVERY}^
           s^@@ETCD_NAME@@^${ETCD_MACHINES[$i]}^
           s^@@CONTAINER_HOST@@^${ETCD_MACHINES[$i]}^" \
          < ${DIR}/etcd_container.yaml  > ${MANIFEST}

  echo "Recreating instance ${ETCD_MACHINES[$i]}"
  ${GCLOUD} compute instances create -q ${ETCD_MACHINES[${i}]} \
      --zone ${ETCD_ZONES[${i}]} \
      --machine-type ${ETCD_MACHINE_TYPE} \
      --image container-vm \
      --disk name=${ETCD_DISKS[${i}]},mode=rw,boot=no,auto-delete=no \
      --tags etcd-node \
      --scopes "monitoring,storage-ro,compute-ro,logging-write" \
      --metadata-from-file startup-script=${DIR}/node_init.sh,google-container-manifest=${MANIFEST}

  set +e
  echo "Waiting for instance ${ETCD_MACHINES[${i}]}..."
  WaitForStatus instances ${ETCD_MACHINES[${i}]} ${ETCD_ZONES[${i}]} RUNNING
  echo "Waiting for etcd service on ${ETCD_MACHINES[${i}]}..."
  WaitHttpStatus ${ETCD_MACHINES[${i}]} ${ETCD_ZONES[${i}]} /v2/keys/root/cluster_config 200 4001
  set -e
  rm "${MANIFEST}"
done
