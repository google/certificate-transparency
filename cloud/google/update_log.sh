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

Header "Updating log instances..."
for i in `seq 0 $((${LOG_NUM_REPLICAS} - 1))`; do
  echo "Updating ${LOG_MACHINES[${i}]}"
  gcloud compute ssh ${LOG_MACHINES[${i}]} \
      --zone ${LOG_ZONES[${i}]} \
      --command \
          'sudo docker pull gcr.io/'${PROJECT}'/super_duper:test &&
           sudo docker kill $(sudo docker ps | grep super_duper | awk -- "{print \$1}" )'
  WaitHttpStatus ${LOG_MACHINES[${i}]} ${LOG_ZONES[${i}]} /ct/v1/get-sth 200
done;


