#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/util.sh

set -e
KUBECTL="gcloud preview container kubectl"

${KUBECTL} create --filename=${DIR}/super_duper_replication.json
${KUBECTL} create --filename=${DIR}/super_duper_service.json

WaitForPod "log-node"
