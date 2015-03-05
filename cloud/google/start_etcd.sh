#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source ${DIR}/util.sh

set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
KUBECTL="gcloud preview container kubectl"
DISCOVERY=$(curl -s https://discovery.etcd.io/new)

echo "Starting etcd replication, using discovery URL '${DISCOVERY}'"
sed -e "s^@@DISCOVERY@@^${DISCOVERY}^" < ${DIR}/etcd_replication.json > /tmp/etcd_replication.json

${KUBECTL} create --filename=/tmp/etcd_replication.json
${KUBECTL} create --filename=${DIR}/etcd_service.json

rm /tmp/etcd_replication.json

WaitForPod "etcd-node"
