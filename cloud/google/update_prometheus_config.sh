#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
CLOUD="gcloud"
TMP_CONFIG="/tmp/prometheus.conf"

PROMETHEUS_VM_HOST=$(${CLOUD} preview container pods list | awk -- '
  /prometheus-replication/ { split($5, a, "."); print a[1]}')

LOG_HOSTS=$(${CLOUD} preview container pods list | awk -- '
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



