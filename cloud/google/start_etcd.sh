#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
KUBECTL="gcloud preview container kubectl"

${KUBECTL} create --filename=${DIR}/etcd_replication.json
${KUBECTL} create --filename=${DIR}/etcd_service.json
