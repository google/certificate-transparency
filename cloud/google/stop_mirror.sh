#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/util.sh
source ${DIR}/mirror-config.sh

GCLOUD="gcloud"

Header "Deleting mirror instances..."
for i in ${MIRROR_MACHINES[@]}; do
  echo "Deleting instance ${i}..."
  set +e
  ${GCLOUD} compute instances delete -q --delete-disks all ${i} &
  set -e
done
wait

for i in ${MIRROR_DISKS[@]}; do
  echo "Deleting disk ${i}..."
  set +e
  ${GCLOUD} compute disks delete -q ${i} > /dev/null &
  set -e
done
wait


