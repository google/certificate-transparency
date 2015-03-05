#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/util.sh

set -e
KUBECTL="gcloud preview container kubectl"
REPLICATION="prometheus-replication"

${KUBECTL} create --filename=${DIR}/prometheus_replication.json
${KUBECTL} create --filename=${DIR}/prometheus_service.json

WaitForPod "prometheus-node"
