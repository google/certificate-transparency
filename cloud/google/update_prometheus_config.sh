#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
CLOUD="gcloud"
KUBECTL="gcloud preview container kubectl"
TMP_CONFIG="/tmp/prometheus.conf"

PROMETHEUS_VM_HOST=$(${KUBECTL} get pods -l name=prometheus-node | awk -- '
  /prometheus-replication/ { split($5, a, "."); print a[1]}')

echo "Prometheus running on ${PROMETHEUS_VM_HOST}"

LOG_HOSTS=$(${KUBECTL} get pods -l name=log-node | awk -- '
  BEGIN {
    ORS="\\n"
  }
  /superduper-replication/ {
    print "target: \"http://" $2 ":6962/metrics\""
  }
')

sed -- "s^@@TARGETS@@^${LOG_HOSTS}^g" < ${DIR}/../prometheus/prometheus.conf > ${TMP_CONFIG}

${CLOUD} compute copy-files \
  ${TMP_CONFIG} ${PROMETHEUS_VM_HOST}:.
${CLOUD} compute ssh ${PROMETHEUS_VM_HOST} --command "
  sudo mv prometheus.conf /tmp/prometheus-config/prometheus.conf &&
  sudo chmod 644 /tmp/prometheus-config/prometheus.conf"
${CLOUD} compute ssh ${PROMETHEUS_VM_HOST} --command '
  CONTAINER=$(sudo docker ps | grep k8s_prometheus | awk -- "{print \$1}" ) &&
  echo "Restarting prometheus container ${CONTAINER}..." &&
  sudo docker restart ${CONTAINER}'



