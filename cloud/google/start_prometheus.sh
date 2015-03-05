#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
KUBECTL="gcloud preview container kubectl"
REPLICATION="prometheus-replication"

${KUBECTL} create --filename=${DIR}/prometheus_replication.json

${KUBECTL} get pods | awk -- "
  /${REPLICATION}/ { split(\$5, a, \".\"); print a[1]}"
