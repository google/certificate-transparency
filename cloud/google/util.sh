
function Header() {
  echo
  tput bold
  tput setaf 5
  echo $*
  tput sgr0
}

function WaitForStatus() {
  TYPE=$1
  NAME=$2
  ZONE=$3
  WANT_STATUS=$4
  STATUS=""
  until [[ "${STATUS}" =~ "${WANT_STATUS}" ]]; do
    sleep 1
    STATUS=$(${GCLOUD} compute ${TYPE} describe ${NAME} --zone ${ZONE} | grep "status:")
    echo ${STATUS}
  done
}

function WaitMachineUp() {
  INSTANCE=${1}
  ZONE=${2}
  echo "Waiting for ${INSTANCE}"
  until ${GCLOUD} compute ssh ${INSTANCE} --zone ${ZONE} --command "exit"; do
    sleep 1
    echo -n .
  done
  echo "${1} is up."
}

function WaitHttpStatus() {
  INSTANCE=${1}
  ZONE=${2}
  HTTP_PATH=${3}
  WANTED_STATUS=${4:-200}
  PORT=${5:-80}
  URL=${INSTANCE}:${PORT}${HTTP_PATH}
  echo "Waiting for HTTP ${WANTED_STATUS} from ${URL} "
  ${GCLOUD} compute ssh ${INSTANCE} \
    --zone ${ZONE} \
    --command "
      STATUS_CODE=''
      while [ \"\${STATUS_CODE}\" != \"${WANTED_STATUS}\" ]; do
        STATUS_CODE=\$(curl --write-out %{http_code} \
            --silent \
            --output /dev/null \
            ${URL})
        echo -n .
        sleep 1
      done"
}

function WaitForEtcd() {
  echo "Waiting for etcd @ ${ETCD_MACHINES[1]}"
  while true; do
    ${GCLOUD} compute ssh ${ETCD_MACHINES[1]} \
        --zone ${ETCD_ZONES[1]} \
        --command "\
     until curl -s -L -m 10 localhost:4001/v2/keys/ > /dev/null; do \
       echo -n .; \
       sleep 1; \
     done" && break;
    sleep 1
    echo "Retrying..."
  done
}


function AppendAndJoin {
  local SUFFIX=${1}
  local SEPARATOR=${2}
  shift 2
  local ARRAY="$*"
  local o="$( printf "${SEPARATOR}%s${SUFFIX}" ${ARRAY} )"
  local o="${o:${#SEPARATOR}}" # remove leading separator
  echo "${o}"
}

function PopulateEtcdForLog() {
  export PUT="curl -s -L -X PUT --retry 10"
  export ETCD="${ETCD_MACHINES[1]}:4001"
  ${GCLOUD} compute ssh ${ETCD_MACHINES[1]} \
      --zone ${ETCD_ZONES[1]} \
      --command "\
    ${PUT} ${ETCD}/v2/keys/root/serving_sth && \
    ${PUT} ${ETCD}/v2/keys/root/cluster_config && \
    ${PUT} ${ETCD}/v2/keys/root/sequence_mapping && \
    ${PUT} ${ETCD}/v2/keys/root/entries/ -d dir=true && \
    ${PUT} ${ETCD}/v2/keys/root/nodes/ -d dir=true"

  ${GCLOUD} compute ssh ${ETCD_MACHINES[1]} \
      --zone ${ETCD_ZONES[1]} \
      --command "\
    sudo docker run gcr.io/${PROJECT}/ct-log:test \
      /usr/local/bin/ct-clustertool initlog \
      --key=/usr/local/etc/server-key.pem \
      --etcd_servers=${ETCD_MACHINES[1]}:4001 \
      --logtostderr"
}

function PopulateEtcdForMirror() {
  export PUT="curl -s -L -X PUT --retry 10"
  export ETCD="${ETCD_MACHINES[1]}:4001"
  ${GCLOUD} compute ssh ${ETCD_MACHINES[1]} \
      --zone ${ETCD_ZONES[1]} \
      --command "\
    ${PUT} ${ETCD}/v2/keys/root/serving_sth && \
    ${PUT} ${ETCD}/v2/keys/root/cluster_config && \
    ${PUT} ${ETCD}/v2/keys/root/nodes/ -d dir=true"
}

function PopulateEtcd() {
  case "${INSTANCE_TYPE}" in
    "log")
      PopulateEtcdForLog
      ;;
    "mirror")
      PopulateEtcdForMirror
      ;;
    *)
      echo "Unknown INSTANCE_TYPE: ${INSTANCE_TYPE}"
      exit 1
  esac
}


