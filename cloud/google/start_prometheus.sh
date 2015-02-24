#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
CLOUD="gcloud preview"
REPLICATION="prometheus-replication"

${CLOUD} container replicationcontrollers create \
  --config-file=${DIR}/prometheus_replication.json

${CLOUD} container pods list | awk -- "
  /${REPLICATION}/ { split(\$5, a, \".\"); print a[1]}"
