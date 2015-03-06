#!/bin/bash
set -e
KUBECTL="gcloud preview container kubectl"
REPLICATION="etcd-replication"

${KUBECTL} stop rc ${REPLICATION}
${KUBECTL} delete service etcd-service
