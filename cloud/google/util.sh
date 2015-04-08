
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

function WaitMachineUp() {
  echo "Waiting for ${1}"
  until ${GCLOUD} compute ssh ${1} -c "logout"; do
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


