export PROJECT=${PROJECT:-your-gce-project}
export CLUSTER=${CLUSTER:-${USER}-ctmirror}
export REGION=${REGION:-europe-west1}
export ZONE=${ZONE:-${REGION}-b}
export GCS_BUCKET=${GCS_BUCKET:-${PROJECT}_ctlog_images}

export ETCD_NUM_REPLICAS=3
export ETCD_DISK_SIZE=200GB
export ETCD_BASE_NAME="${CLUSTER}-etcd"
export ETCD_MACHINE_TYPE=n1-standard-2
declare -a ETCD_MACHINES ETCD_DISKS
export ETCD_MACHINES ETCD_DISKS
for i in $(seq ${ETCD_NUM_REPLICAS}); do
  ETCD_MACHINES[$i]="${CLUSTER}-etcd-$i"
  ETCD_DISKS[$i]="${CLUSTER}-etcd-disk-$i"
done


export MIRROR_TARGET_URL="http://ct.googleapis.com/pilot"
# Public key relative to the cloud/keys directory:
export MIRROR_TARGET_PUBLIC_KEY=pilot.pem
export MIRROR_NUM_REPLICAS=3
export MIRROR_DISK_SIZE=200GB
export MIRROR_BASE_NAME="${CLUSTER}-mirror"
export MIRROR_MACHINE_TYPE=n1-highmem-2
declare -a MIRROR_MACHINES MIRROR_DISKS
export MIRROR_MACHINES MIRROR_DISKS
for i in $(seq ${MIRROR_NUM_REPLICAS}); do
  MIRROR_MACHINES[$i]="${CLUSTER}-mirror-$i"
  MIRROR_DISKS[$i]="${CLUSTER}-mirror-disk-$i"
done


export PROMETHEUS_NUM_REPLICAS=1
export PROMETHEUS_DISK_SIZE=50GB
export PROMETHEUS_BASE_NAME="${CLUSTER}-prometheus"
export PROMETHEUS_MACHINE_TYPE=n1-standard-1
declare -a PROMETHEUS_MACHINES MIRROR_DISKS
export PROMETHEUS_MACHINES MIRROR_DISKS
for i in $(seq ${PROMETHEUS_NUM_REPLICAS}); do
  PROMETHEUS_MACHINES[$i]="${CLUSTER}-prometheus-$i"
  PROMETHEUS_DISKS[$i]="${CLUSTER}-prometheus-disk-$i"
done


echo "============================================================="
echo "Cluster config:"
echo "PROJECT:     ${PROJECT}"
echo "CLUSTER:     ${CLUSTER}"
echo "REGION:      ${REGION}"
echo "ZONE:        ${ZONE}"
echo "Num etcd:    ${ETCD_NUM_REPLICAS}"
echo "Num mirrors: ${MIRROR_NUM_REPLICAS}"
echo "Num prom:    ${PROMETHEUS_NUM_REPLICAS}"
echo "============================================================="
echo
