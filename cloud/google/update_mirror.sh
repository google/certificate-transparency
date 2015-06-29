#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
if [ "$1" == "" ]; then
  echo "Usage $0: <config-file>"
  exit 1
fi
source ${DIR}/util.sh
source ${DIR}/config.sh $1

set -e
GCLOUD="gcloud"

Header "Updating mirror instances..."
# TODO(alcutter): Wait for each task (or zone?) to be healthy before
# proceeding.
for i in `seq 0 $((${MIRROR_NUM_REPLICAS} - 1))`; do
  echo "Updating ${MIRROR_MACHINES[${i}]}"
  gcloud compute ssh ${MIRROR_MACHINES[${i}]} \
      --zone ${MIRROR_ZONES[${i}]} \
      --command \
          'sudo docker pull gcr.io/'${PROJECT}'/super_mirror:test &&
           sudo docker kill $(sudo docker ps | grep super_mirror | awk -- "{print \$1}" )'
done;


