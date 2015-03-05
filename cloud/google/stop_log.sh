#!/bin/bash
set -e
KUBECTL="gcloud preview container kubectl"
REPLICATION="superduper-replication"

${KUBECTL} stop rc ${REPLICATION}
${KUBECTL} delete service super-duper-service
