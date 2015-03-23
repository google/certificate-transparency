#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/util.sh
source ${DIR}/config.sh

GCLOUD="gcloud"

Header "Deleting prometheus instances..."
for i in ${PROMETHEUS_MACHINES[@]}; do
  echo "Deleting instance ${i}..."
  set +e
  ${GCLOUD} compute instances delete -q --delete-disks all ${i} &
  set -e
done
wait

for i in ${PROMETHEUS_DISKS[@]}; do
  echo "Deleting disk ${i}..."
  set +e
  ${GCLOUD} compute disks delete -q ${i} > /dev/null &
  set -e
done
wait


