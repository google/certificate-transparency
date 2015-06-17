export PROJECT=${PROJECT:-your-gce-project}
export CLUSTER=${CLUSTER:-${USER}-ctlog}
export REGION=${REGION:-europe-west1}
# space separated list of zones within ${REGION} in which to run jobs.
# e.g. "b c d"
export ZONES="b c d"
export GCS_BUCKET=${GCS_BUCKET:-${PROJECT}_ctlog_images}

export ETCD_NUM_REPLICAS_PER_ZONE=1
export ETCD_DISK_SIZE=200GB
export ETCD_BASE_NAME="${CLUSTER}-etcd"
export ETCD_MACHINE_TYPE=n1-standard-2
declare -a ETCD_ZONES ETCD_MACHINES ETCD_DISKS
export ETCD_ZONES ETCD_MACHINES ETCD_DISKS
export ETCD_NUM_REPLICAS=0
for z in ${ZONES}; do
  for i in $(seq ${ETCD_NUM_REPLICAS_PER_ZONE}); do
    ETCD_ZONES[${ETCD_NUM_REPLICAS}]="${REGION}-${z}"
    ETCD_MACHINES[${ETCD_NUM_REPLICAS}]="${CLUSTER}-etcd-${z}-${i}"
    ETCD_DISKS[${ETCD_NUM_REPLICAS}]="${CLUSTER}-etcd-disk-${z}-${i}"
    ETCD_NUM_REPLICAS=$((${ETCD_NUM_REPLICAS} + 1))
  done
done


export LOG_NUM_REPLICAS_PER_ZONE=2
export LOG_DISK_SIZE=200GB
export LOG_BASE_NAME="${CLUSTER}-log"
export LOG_MACHINE_TYPE=n1-highmem-2
declare -a LOG_ZONES LOG_MACHINES LOG_DISKS
export LOG_ZONES LOG_MACHINES LOG_DISKS
export LOG_NUM_REPLICAS=0
for z in ${ZONES}; do
  for i in $(seq ${LOG_NUM_REPLICAS_PER_ZONE}); do
    LOG_ZONES[${LOG_NUM_REPLICAS}]="${REGION}-${z}"
    LOG_MACHINES[${LOG_NUM_REPLICAS}]="${CLUSTER}-log-${z}-${i}"
    LOG_DISKS[${LOG_NUM_REPLICAS}]="${CLUSTER}-log-disk-${z}-${i}"
    LOG_NUM_REPLICAS=$((${LOG_NUM_REPLICAS} + 1))
  done
done


export PROMETHEUS_NUM_REPLICAS_PER_ZONE=1
export PROMETHEUS_DISK_SIZE=50GB
export PROMETHEUS_BASE_NAME="${CLUSTER}-prometheus"
export PROMETHEUS_MACHINE_TYPE=n1-standard-1
declare -a PROMETHEUS_ZONES PROMETHEUS_MACHINES MIRROR_DISKS
export PROMETHEUS_ZONES PROMETHEUS_MACHINES MIRROR_DISKS
export PROMETHEUS_NUM_REPLICAS=0
for z in ${ZONES}; do
  for i in $(seq ${PROMETHEUS_NUM_REPLICAS_PER_ZONE}); do
    PROMETHEUS_ZONES[${PROMETHEUS_NUM_REPLICAS}]="${REGION}-${z}"
    PROMETHEUS_MACHINES[${PROMETHEUS_NUM_REPLICAS}]="${CLUSTER}-prometheus-${z}-${i}"
    PROMETHEUS_DISKS[${PROMETHEUS_NUM_REPLICAS}]="${CLUSTER}-prometheus-disk-${z}-${i}"
    PROMETHEUS_NUM_REPLICAS=$((${PROMETHEUS_NUM_REPLICAS} + 1))
  done
done


echo "============================================================="
echo "Cluster config:"
echo "PROJECT:     ${PROJECT}"
echo "CLUSTER:     ${CLUSTER}"
echo "REGION:      ${REGION}"
echo "ZONES:       ${ZONES}"
echo "Num etcd:    ${ETCD_NUM_REPLICAS}"
echo "Num mirrors: ${MIRROR_NUM_REPLICAS}"
echo "Num prom:    ${PROMETHEUS_NUM_REPLICAS}"
echo "============================================================="
echo
