#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
KUBECTL="gcloud preview container kubectl"
REPLICATION="prometheus-replication"

${KUBECTL} stop rc ${REPLICATION}
${KUBECTL} delete service prometheus-service
