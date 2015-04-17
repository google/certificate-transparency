#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/config.sh
source ${DIR}/util.sh

set -e
GCLOUD="gcloud"

LOG_HOSTS=$(
  for i in ${LOG_MACHINES[@]}; do
    echo -n "target: \"http://${i}:80/metrics\"\n";
    echo -n "target: \"http://${i}:8080/metrics\"\n";
  done)
ETCD_HOSTS=$(
  for i in ${ETCD_MACHINES[@]}; do
    echo -n "target: \"http://${i}:8080/metrics\"\n";
  done)

export TMP_CONFIG=/tmp/prometheus.conf
sed -- "s%@@LOG_TARGETS@@%${LOG_HOSTS}%g
        s%@@ETCD_TARGETS@@%${ETCD_HOSTS}%g" < ${DIR}/../prometheus/prometheus.conf > ${TMP_CONFIG}


for i in ${PROMETHEUS_MACHINES[@]}; do
  WaitMachineUp ${i}
  ${GCLOUD} compute copy-files \
    ${TMP_CONFIG} ${i}:.
  ${GCLOUD} compute ssh ${i} --command "
    sudo mkdir -p /data/prometheus/config &&
    sudo mv prometheus.conf /data/prometheus/config/prometheus.conf &&
    sudo chmod 644 /data/prometheus/config/prometheus.conf"
  ${GCLOUD} compute ssh ${i} --command '
    CONTAINER=$(sudo docker ps | grep prometheus | awk -- "{print \$1}" )
    if [ "${CONTAINER}" != "" ]; then
      echo "Restarting prometheus container ${CONTAINER}..."
      sudo docker restart ${CONTAINER}
    else
      echo "Prometheus container not yet running."
    fi'
done
