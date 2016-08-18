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
OBJNAME=get-sth-check
PRESENT=`${GCLOUD} compute http-health-checks list ${OBJNAME} | grep ${OBJNAME} || true`
if [ "$PRESENT" == "" ]; then
  ${GCLOUD} compute http-health-checks create ${OBJNAME} \
      --port 80 \
      --request-path /ct/v1/get-sth
else
  echo "  ...${OBJNAME} already present"
fi
echo "  firewall-rules create..."
OBJNAME=${INSTANCE_TYPE}-node-80
PRESENT=`${GCLOUD} compute firewall-rules list ${OBJNAME} | grep ${OBJNAME} || true`
if [ "$PRESENT" == "" ]; then
  ${GCLOUD} compute firewall-rules create ${OBJNAME} \
      --allow tcp:80 \
      --target-tags ${INSTANCE_TYPE}-node
else
  echo "  ...${OBJNAME} already present"
fi

echo "  instance-groups unmanaged create..."
for zone in ${ZONE_LIST}; do
  OBJNAME=${INSTANCE_TYPE}-group-${zone}
  PRESENT=`${GCLOUD} compute instance-groups unmanaged list ${OBJNAME} | grep ${OBJNAME} || true`
  if [ "$PRESENT" == "" ]; then
    ${GCLOUD} compute instance-groups unmanaged \
        create "${OBJNAME}" \
        --zone ${zone} &
  else
    echo "  ...${OBJNAME} already present"
  fi
done
wait

echo "  instance-groups unmanaged add-instances..."
for i in `seq 0 $((${NODE_NUM_REPLICAS} - 1))`; do
  ZONE=${NODE_ZONES[${i}]}
  MACHINE="${NODE_MACHINES[${i}]}"
  OBJNAME=${INSTANCE_TYPE}-group-${ZONE}
  PRESENT=`${GCLOUD} compute instance-groups unmanaged list-instances ${OBJNAME} --zone ${ZONE} | grep ${MACHINE} || true`
  echo "PRESENT=$PRESENT:"
  if [ "$PRESENT" == "" ]; then
    ${GCLOUD} compute instance-groups unmanaged add-instances \
        "${OBJNAME}" \
        --zone ${ZONE} \
        --instances ${MACHINE} &
  else
    echo "  ...${INSTANCE_TYPE}-group-${NODE_ZONES[${i}]} already contains ${NODE_MACHINES[${i}]}"
  fi
done
wait

echo "  addresses create..."
OBJNAME=${INSTANCE_TYPE}-ip
PRESENT=`${GCLOUD} compute addresses list "${OBJNAME}" | grep ${OBJNAME} || true`
if [ "$PRESENT" == "" ]; then
  ${GCLOUD} compute addresses create "${OBJNAME}" \
      --global
else
  echo "  ...${OBJNAME} already present"
fi
export EXTERNAL_IP=$(${GCLOUD} compute addresses list "${OBJNAME}" |
                     awk -- "/${OBJNAME}/ {print \$2}")
echo "Service IP: ${EXTERNAL_IP}"


echo "  backend-services create..."
OBJNAME=${INSTANCE_TYPE}-lb-backend
PRESENT=`${GCLOUD} compute backend-services list ${OBJNAME} | grep ${OBJNAME} || true`
if [ "$PRESENT" == "" ]; then
  ${GCLOUD} compute backend-services create "${OBJNAME}" \
      --http-health-checks "get-sth-check" \
      --timeout "30"
else
  echo "  ...${OBJNAME} already present"
fi

echo "    backend-services add-backend..."
for zone in ${ZONE_LIST}; do
  SUBOBJNAME=${INSTANCE_TYPE}-group-${zone}
  PRESENT=`${GCLOUD} compute backend-services list ${OBJNAME} | grep ${SUBOBJNAME} || true`
  if [ "$PRESENT" == "" ]; then
    ${GCLOUD} compute backend-services add-backend "${OBJNAME}" \
      --instance-group "${SUBOBJNAME}" \
      --instance-group-zone ${zone} \
      --balancing-mode "UTILIZATION" \
      --capacity-scaler "1" \
      --max-utilization "0.8"
  else
    echo "    ...${SUBOBJNAME} already present in ${OBJNAME}"
  fi
done

echo "  url-maps create..."
OBJNAME=${INSTANCE_TYPE}-lb-url-map
PRESENT=`${GCLOUD} compute url-maps list ${OBJNAME} | grep ${OBJNAME} || true`
if [ "$PRESENT" == "" ]; then
  ${GCLOUD} compute url-maps create "${OBJNAME}" \
      --default-service "${INSTANCE_TYPE}-lb-backend"
else
  echo "  ...${OBJNAME} already present"
fi

echo "  target-http-proxies create..."
OBJNAME=${INSTANCE_TYPE}-lb-http-proxy
PRESENT=`${GCLOUD} compute target-http-proxies list ${OBJNAME} | grep ${OBJNAME} || true`
if [ "$PRESENT" == "" ]; then
  ${GCLOUD} compute target-http-proxies create "${OBJNAME}" \
      --url-map "${INSTANCE_TYPE}-lb-url-map"
else
  echo "  ...${OBJNAME} already present"
fi

echo "  forwarding-rules create..."
OBJNAME=${INSTANCE_TYPE}-fwd
PRESENT=`${GCLOUD} compute forwarding-rules list ${OBJNAME} | grep ${OBJNAME} || true`
if [ "$PRESENT" == "" ]; then
  ${GCLOUD} compute forwarding-rules create "${OBJNAME}" \
      --global \
      --address "${EXTERNAL_IP}" \
      --ip-protocol "TCP" \
      --ports "80" \
      --target-http-proxy "${INSTANCE_TYPE}-lb-http-proxy"
else
  echo "  ...${OBJNAME} already present"
fi

echo "============================================================="
echo "External IPs:"
${GCLOUD} compute forwarding-rules list
echo "============================================================="

