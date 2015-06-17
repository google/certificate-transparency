
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

function AppendAndJoin {
  local SUFFIX=${1}
  local SEPARATOR=${2}
  shift 2
  local ARRAY="$*"
  local o="$( printf "${SEPARATOR}%s${SUFFIX}" ${ARRAY} )"
  local o="${o:${#SEPARATOR}}" # remove leading separator
  echo "${o}"
}


