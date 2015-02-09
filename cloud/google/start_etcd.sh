#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
CLOUD="gcloud preview"

${CLOUD} container replicationcontrollers create --config-file=${DIR}/etcd_replication.json
${CLOUD} container services create --config-file=${DIR}/etcd_service.json
