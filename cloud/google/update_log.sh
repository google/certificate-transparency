#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
if [ "$1" == "" ]; then
  echo "Usage $0: <config-file>"
  exit 1
fi
source ${DIR}/util.sh
source ${DIR}/config.sh $1

set -e
GCLOUD="gcloud --project ${PROJECT}"

Header "Updating log instances..."
i=0
while [ $i -lt ${LOG_NUM_REPLICAS} ]; do
  echo "Updating ${LOG_MACHINES[${i}]}"

  METADATA=$(mktemp)
  echo "${LOG_META[${i}]}" > ${METADATA}

  if ! gcloud compute instances add-metadata \
      ${LOG_MACHINES[${i}]} \
      --zone ${LOG_ZONES[${i}]} \
      --metadata-from-file google-container-manifest=${METADATA}; then
    echo "Retrying"
    continue
  fi

  if ! gcloud compute ssh ${LOG_MACHINES[${i}]} \
      --zone ${LOG_ZONES[${i}]} \
      --command \
          'sudo docker pull gcr.io/'${PROJECT}'/ct-log:test &&
           sudo docker kill $(sudo docker ps | grep ct-log | awk -- "{print \$1}" )'; then
    echo "Retrying"
    continue
  fi

  WaitHttpStatus ${LOG_MACHINES[${i}]} ${LOG_ZONES[${i}]} /ct/v1/get-sth 200
  i=$(($i + 1))

  rm "${METADATA}"
done;


