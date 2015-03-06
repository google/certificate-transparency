export KUBECTL="gcloud preview container kubectl"

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


