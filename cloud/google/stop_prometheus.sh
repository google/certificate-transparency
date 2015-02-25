#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
CLOUD="gcloud preview"
REPLICATION="prometheus-replication"

${CLOUD} container replicationcontrollers delete ${REPLICATION}

for i in $(${CLOUD} container pods list | grep ${REPLICATION} | cut -f 1 -d' '); do
  ${CLOUD} container pods delete $i;
done;
