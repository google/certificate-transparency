#!/bin/bash
#
# DANGER! DANGER! DANGER!
# This script deletes & re-creates the etcd VMs, and will permanently delete
# all etcd cluster data in the process.
# DANGER! DANGER! DANGER!
#
# This script is mostly useful for MIRRORS when the etcd cluster has fallen
# completely out of quorum (perhaps because all IP addresses changed), and
# needs to be rebuilt.
#
# When used with CT MIRRORs, the CT cluster is able to recover since all of the
# required data is held on the individual ct-mirror nodes and etcd is
# repopulated.
#
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
if [ "$1" == "" ]; then
  echo "Usage: $0 <config.sh file>"
  exit 1;
fi
source ${DIR}/config.sh $1
source ${DIR}/util.sh

set -e
GCLOUD="gcloud --project ${PROJECT}"
CONFIG_FILE=${1}

Header "######################################################################"
Header "Starting ${CONFIG_FILE}"
Header "######################################################################"


echo "============================================================="
echo "Deleting old etcd instances..."
${DIR}/stop_etcd.sh ${CONFIG_FILE}

echo "============================================================="
echo "Creating etcd instances..."
${DIR}/start_etcd.sh ${CONFIG_FILE}

WaitForEtcd

echo "============================================================="
echo "Populating etcd with default entries..."

PopulateEtcd

echo

Header "######################################################################"
Header "${CONFIG_FILE} Done."
Header "######################################################################"



