export KUBECTL="gcloud preview container kubectl"

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
  WANT_STATUS=$3
  STATUS=""
  until [[ "${STATUS}" =~ "${WANT_STATUS}" ]]; do
    sleep 1
    STATUS=$(${GCLOUD} compute ${TYPE} describe ${NAME} | grep "status:")
    echo ${STATUS}
  done
}

function WaitForPod() {
  set +e
  NODE_LABEL="name=$1"
  echo "Waiting for $1"

  until [ "${STATE}" != "" ]; do
    echo -n .
    sleep 1
    STATE=$(${KUBECTL} get pods -l "${NODE_LABEL}" -o yaml | \
        grep -i "status: Running" | grep -v "status: Waiting")
  done
  echo
  return 0
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


