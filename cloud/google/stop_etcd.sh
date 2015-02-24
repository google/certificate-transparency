#!/bin/bash
set -e
CLOUD="gcloud preview"
REPLICATION="etcd-replication"

${CLOUD} container replicationcontrollers delete ${REPLICATION}
for i in $(${CLOUD} container pods list | grep ${REPLICATION} | cut -f 1 -d' '); do
  ${CLOUD} container pods delete $i;
done;
${CLOUD} container services delete etcd-service
