#!/bin/bash
#
# Pass a project config file to this command to have it resize all of that
# project's disks to the size dictated by ./config.sh.
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
if [ "$1" == "" ]; then
  echo "Usage: $0 <config-file>"
  exit 1
fi
CONFIG_FILE="$1"

. ${DIR}/config.sh ${CONFIG_FILE}
GCLOUD="gcloud --project ${PROJECT}"

case "${INSTANCE_TYPE}" in
  "mirror")
    NUM_REPLICAS=(${MIRROR_NUM_REPLICAS[@]})
    DISKS=(${MIRROR_DISKS[@]})
    MACHINES=(${MIRROR_MACHINES[@]})
    ZONES=(${MIRROR_ZONES[@]})
    NEW_SIZE=(${MIRROR_DISK_SIZE[@]})
    ;;
  "log")
    NUM_REPLICAS=(${LOG_NUM_REPLICAS[@]})
    DISKS=(${LOG_DISKS[@]})
    MACHINES=(${LOG_MACHINES[@]})
    ZONES=(${LOG_ZONES[@]})
    NEW_SIZE=(${LOG_DISK_SIZE[@]})
   ;;
  "etcd")
    NUM_REPLICAS=(${ETCD_NUM_REPLICAS[@]})
    DISKS=(${ETCD_DISKS[@]})
    MACHINES=(${ETCD_MACHINES[@]})
    ZONES=(${ETCD_ZONES[@]})
    NEW_SIZE=(${ETCD_DISK_SIZE[@]})
   ;;
  "prometheus")
    NUM_REPLICAS=(${PROMETHEUS_NUM_REPLICAS[@]})
    DISKS=(${PROMETHEUS_DISKS[@]})
    MACHINES=(${PROMETHEUS_MACHINES[@]})
    ZONES=(${PROMETHEUS_ZONES[@]})
    NEW_SIZE=(${PROMETHEUS_DISK_SIZE[@]})
   ;;
  *)
    echo "Unknown INSTANCE_TYPE: ${INSTANCE_TYPE}"
    exit 1
esac

for i in $(seq 0 $((${NUM_REPLICAS} - 1))); do
  ZONE="${ZONES[${i}]}"
  MACHINE="${MACHINES[${i}]}"
  DISK="${DISKS[${i}]}"

  echo "Resizing ${DISK} to ${NEW_SIZE}..."
  if ! ${GCLOUD} compute disks resize "${DISK}" \
    --zone "${ZONE}" \
    --size "${NEW_SIZE}"; then
    continue
  fi

  echo "Resizing file system on ${MACHINE}..."
  ${GCLOUD} compute ssh "${MACHINE}" \
    --zone "${ZONE}" \
    --command 'sudo resize2fs "$(findmnt -n -o SOURCE --target /data)"'
done
