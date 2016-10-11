#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
if [ "$1" == "" ]; then
  echo "Usage: $0 <config-file>"
  exit 1
fi
CONFIG_FILE="$1"

. ${DIR}/config.sh ${CONFIG_FILE}
GCLOUD="gcloud --project ${PROJECT}"

if [ ! -x ${DIR}/../../cpp/tools/ct-clustertool ]; then
  echo "Please ensure that cpp/tools/ct-clustertool is built."
  exit 1
fi

echo "============================================================="
echo "Creating new GCE-based ${INSTANCE_TYPE} cluster."
echo "============================================================="

echo "============================================================="
echo "Creating etcd instances..."
${DIR}/start_etcd.sh ${CONFIG_FILE}

WaitForEtcd

echo "============================================================="
echo "Populating etcd with default entries..."

PopulateEtcd


echo "============================================================="
echo "Creating distributed CT log ${INSTANCE_TYPE} instances..."
case "${INSTANCE_TYPE}" in
  "log")
    ${DIR}/start_log.sh ${CONFIG_FILE}
    ;;
  "mirror")
    ${DIR}/start_mirror.sh ${CONFIG_FILE}
    ;;
  *)
    echo "Unknown INSTANCE_TYPE: ${INSTANCE_TYPE}"
    exit 1
esac

if [ "${MONITORING}" == "prometheus" ]; then
  echo "============================================================="
  echo "Starting prometheus..."
  ${DIR}/start_prometheus.sh ${CONFIG_FILE}
  ${DIR}/update_prometheus_config.sh ${CONFIG_FILE}
fi

${DIR}/configure_service.sh ${CONFIG_FILE}

echo "Job done!"
