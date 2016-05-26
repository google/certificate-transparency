#!/bin/bash
set -e
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
GCLOUD="gcloud"
if [ "$1" == "" ]; then
  echo "Usage: $0 <config-file>"
  exit 1
fi
CONFIG_FILE="$1"

. ${DIR}/config.sh ${CONFIG_FILE}

case "${INSTANCE_TYPE}" in
  "mirror")
    eval $(typeset -A -p MIRROR_ZONES | sed 's/MIRROR_ZONES=/NODE_ZONES=/')
    eval $(typeset -A -p MIRROR_MACHINES | \
           sed 's/MIRROR_MACHINES=/NODE_MACHINES=/')
    export NODE_NUM_REPLICAS=${MIRROR_NUM_REPLICAS}
    export NODE_ZONES
    ;;
  "log")
    eval $(typeset -A -p LOG_ZONES | sed 's/LOG_ZONES=/NODE_ZONES=/')
    eval $(typeset -A -p LOG_MACHINES | \
           sed 's/LOG_MACHINES=/NODE_MACHINES=/')
    export NODE_NUM_REPLICAS=${LOG_NUM_REPLICAS}
    export NODE_ZONES
   ;;
  *)
    echo "Unknown INSTANCE_TYPE: ${INSTANCE_TYPE}"
    exit 1
esac

ZONE_LIST=$(echo ${NODE_ZONES[*]} | tr " " "\n" | sort | uniq )

echo "============================================================="
echo "Creating network rules..."
echo "  http-health-checks create..."
PRESENT=`gcloud compute http-health-checks list get-sth-check | grep get-sth-check`
if [ "$PRESENT" == "" ]; then
  gcloud compute http-health-checks create get-sth-check \
      --port 80 \
      --request-path /ct/v1/get-sth
else
  echo "  ...get-sth-check already present"
fi
echo "  firewall-rules create..."
PRESENT=`gcloud compute firewall-rules list ${INSTANCE_TYPE}-node-80 | grep ${INSTANCE_TYPE}-node-80`
if [ "$PRESENT" == "" ]; then
  gcloud compute firewall-rules create ${INSTANCE_TYPE}-node-80 \
      --allow tcp:80 \
      --target-tags ${INSTANCE_TYPE}-node
else
  echo "  ...${INSTANCE_TYPE}-node already present"
fi

echo "  instance-groups unmanaged create..."
for zone in ${ZONE_LIST}; do
  PRESENT=`gcloud compute instance-groups unmanaged list ${INSTANCE_TYPE}-group-${zone} | grep ${INSTANCE_TYPE}-group-${zone}`
  if [ "$PRESENT" == "" ]; then
    gcloud compute instance-groups unmanaged \
        create "${INSTANCE_TYPE}-group-${zone}" \
        --zone ${zone} &
  else
    echo "  ...${INSTANCE_TYPE}-group-${zone} already present"
  fi
done
wait

echo "  instance-groups unmanaged add-instances..."
for i in `seq 0 $((${NODE_NUM_REPLICAS} - 1))`; do
  PRESENT=`gcloud compute instance-groups unmanaged list-instances ${INSTANCE_TYPE}-group-${NODE_ZONES[${i}]} --zone ${NODE_ZONES[${i}]}| grep ${NODE_MACHINES[${i}]}`
  if [ "$PRESENT" == "" ]; then
    gcloud compute instance-groups unmanaged add-instances \
        "${INSTANCE_TYPE}-group-${NODE_ZONES[${i}]}" \
        --zone ${NODE_ZONES[${i}]} \
        --instances ${NODE_MACHINES[${i}]} &
  else
    echo "  ...${INSTANCE_TYPE}-group-${NODE_ZONES[${i}]} already contains ${NODE_MACHINES[${i}]}"
  fi
done
wait

echo "  addresses create..."
PRESENT=`gcloud compute addresses list "${INSTANCE_TYPE}-ip" | grep "${INSTANCE_TYPE}-ip"`
if [ "$PRESENT" == "" ]; then
  gcloud compute addresses create "${INSTANCE_TYPE}-ip" \
      --global
else
  echo "  ...${INSTANCE_TYPE}-ip already present"
fi
export EXTERNAL_IP=$(gcloud compute addresses list "${INSTANCE_TYPE}-ip" |
                     awk -- "/${INSTANCE_TYPE}-ip/ {print \$2}")
echo "Service IP: ${EXTERNAL_IP}"


echo "  backend-services create..."
PRESENT=`gcloud compute backend-services list ${INSTANCE_TYPE}-lb-backend | grep ${INSTANCE_TYPE}-lb-backend`
if [ "$PRESENT" == "" ]; then
  gcloud compute backend-services create "${INSTANCE_TYPE}-lb-backend" \
      --http-health-check "get-sth-check" \
      --timeout "30"
else
  echo "  ...${INSTANCE_TYPE}-lb-backend already present"
fi

echo "  backend-services add-backend..."
for zone in ${ZONE_LIST}; do
  PRESENT=`gcloud compute backend-services list ${INSTANCE_TYPE}-lb-backend | grep ${INSTANCE_TYPE}-group-${zone}`
  if [ "$PRESENT" == "" ]; then
    gcloud compute backend-services add-backend "${INSTANCE_TYPE}-lb-backend" \
      --instance-group "${INSTANCE_TYPE}-group-${zone}" \
      --zone ${zone} \
      --balancing-mode "UTILIZATION" \
      --capacity-scaler "1" \
      --max-utilization "0.8"
  else
    echo "  ...${INSTANCE_TYPE}-group-${zone} already present in ${INSTANCE_TYPE}-lb-backend"
  fi
done

echo "  url-maps create..."
PRESENT=`gcloud compute url-maps list ${INSTANCE_TYPE}-lb-url-map | grep ${INSTANCE_TYPE}-lb-url-map`
if [ "$PRESENT" == "" ]; then
  gcloud compute url-maps create "${INSTANCE_TYPE}-lb-url-map" \
      --default-service "${INSTANCE_TYPE}-lb-backend"
else
  echo "  ...${INSTANCE_TYPE}-lb-url-map already present"
fi

echo "  target-http-proxies create..."
PRESENT=`gcloud compute target-http-proxies list ${INSTANCE_TYPE}-lb-http-proxy | grep ${INSTANCE_TYPE}-lb-http-proxy`
if [ "$PRESENT" == "" ]; then
  gcloud compute target-http-proxies create "${INSTANCE_TYPE}-lb-http-proxy" \
      --url-map "${INSTANCE_TYPE}-lb-url-map"
else
  echo "  ...${INSTANCE_TYPE}-lb-http-proxy already present"
fi

echo "  forwarding-rules create..."
PRESENT=`gcloud compute forwarding-rules list ${INSTANCE_TYPE}-fwd | grep ${INSTANCE_TYPE}-fwd`
if [ "$PRESENT" == "" ]; then
  gcloud compute forwarding-rules create "${INSTANCE_TYPE}-fwd" \
      --global \
      --address "${EXTERNAL_IP}" \
      --ip-protocol "TCP" \
      --port-range "80" \
      --target-http-proxy "${INSTANCE_TYPE}-lb-http-proxy"
else
  echo "  ...${INSTANCE_TYPE}-fwd already present"
fi

echo "============================================================="
echo "External IPs:"
gcloud compute forwarding-rules list
echo "============================================================="

