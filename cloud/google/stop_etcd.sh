#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/util.sh
source ${DIR}/config.sh

GCLOUD="gcloud"

Header "Deleting etcd instances..."
for i in ${ETCD_MACHINES[@]}; do
  echo "Deleting instance ${i}..."
  set +e
  ${GCLOUD} compute instances delete -q --delete-disks all ${i} &
  set -e
done
wait

for i in ${ETCD_DISKS[@]}; do
  echo "Deleting disk ${i}..."
  set +e
  ${GCLOUD} compute disks delete -q ${i} > /dev/null &
  set -e
done
wait


