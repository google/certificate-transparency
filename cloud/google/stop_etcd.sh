#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
if [ "$1" == "" ]; then
  echo "Usage: $0 <config.sh file>"
  exit 1;
fi
source $1
source ${DIR}/util.sh

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


