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

LOG_HOSTS=$(
  for i in ${LOG_MACHINES[@]}; do
    echo -n "    - ${i}.c.${PROJECT}.internal:80\n";
    echo -n "    - ${i}.c.${PROJECT}.internal:8080\n";
  done)
MIRROR_HOSTS=$(
  for i in ${MIRROR_MACHINES[@]}; do
    echo -n "    - ${i}.c.${PROJECT}.internal:80\n";
    echo -n "    - ${i}.c.${PROJECT}.internal:8080\n";
  done)
ETCD_HOSTS=$(
  for i in ${ETCD_MACHINES[@]}; do
    echo -n "    - ${i}.c.${PROJECT}.internal:8080\n";
  done)

export TMP_CONFIG=$(mktemp)
sed -- "s%@@LOG_TARGETS@@%${LOG_HOSTS}%g
        s%@@MIRROR_TARGETS@@%${MIRROR_HOSTS}%g
        s%@@ETCD_TARGETS@@%${ETCD_HOSTS}%g" < ${DIR}/../prometheus/prometheus.conf > ${TMP_CONFIG}


for i in `seq 0 $((${PROMETHEUS_NUM_REPLICAS} - 1))`; do
  INSTANCE=${PROMETHEUS_MACHINES[${i}]}
  ZONE=${PROMETHEUS_ZONES[${i}]}
  WaitMachineUp ${INSTANCE} ${ZONE}

  # Workaround copy-files ignoring the --zone flag:
  ${GCLOUD} config set compute/zone ${ETCD_ZONES[1]}
  ${GCLOUD} compute copy-files \
      --zone ${ZONE} \
      ${TMP_CONFIG} ${INSTANCE}:.
  # Remove workaround
  ${GCLOUD} config unset compute/zone

  ${GCLOUD} compute ssh ${INSTANCE} \
      --zone ${ZONE} \
      --command "
    sudo mkdir -p /data/prometheus/config &&
    sudo mv prometheus.conf /data/prometheus/config/prometheus.conf &&
    sudo chmod 644 /data/prometheus/config/prometheus.conf"
  ${GCLOUD} compute ssh ${INSTANCE} \
      --zone ${ZONE} \
      --command '
    CONTAINER=$(sudo docker ps | grep prometheus | awk -- "{print \$1}" )
    if [ "${CONTAINER}" != "" ]; then
      echo "Restarting prometheus container ${CONTAINER}..."
      sudo docker restart ${CONTAINER}
    else
      echo "Prometheus container not yet running."
    fi'
done

rm ${TMP_CONFIG}
