#!/usr/bin/env bash

# Test a running server. If the certificate directory does not exist,
# a new CA will be created in it.

# Fail on any error
set -e

PASSED=0
FAILED=0

if [ $# \< 2 ]
then
  echo "$0 <certificate directory> <CT server public key> [<server> [<port>]]"
  exit 1
fi

CERT_DIR=$1
CT_KEY=$2
SERVER=${3:-"127.0.0.1"}
# Note: not actually used for HTTP logs...
PORT=${4:-8124}

HTTP_LOG=--http_log

echo $SERVER

. generate_certs.sh

if [ ! -e $CERT_DIR/ca-database ]
then
  echo "Initialise CA"
  ca_setup $CERT_DIR ca false
fi

# FIXME(benl): share with sslconnect_test.sh?
audit() {
  cert_dir=$1
  log_server=$2
  sct=$3

  set +e
  ../client/ct audit --ct_server="$SERVER" --ct_server_port=$PORT \
    --ct_server_public_key=$CT_KEY \
    --ssl_client_ct_data_in=$sct --logtostderr=true $HTTP_LOG
  retcode=$?
  set -e
}

do_audit() {
  ct_data=$1
  T=`date +%s`
  T=`expr $T + 30`

  while true
  do
    audit $CERT_DIR ca $ct_data
    if [ $retcode -eq 0 ]; then
      echo "PASS"
      let PASSED=$PASSED+1
      break
    else
      if [ `date +%s` \> $T ]
      then
	echo "FAIL"
	let FAILED=$FAILED+1
	break
      fi
    fi
    sleep 1
  done
}

get_sth() {
  local file=$1

  ../client/ct sth --ct_server="$SERVER" --ct_server_port=$PORT \
    --ct_server_public_key=$CT_KEY --logtostderr=true $HTTP_LOG \
    --ct_server_response_out=$file
}

consistency() {
  local file1=$1
  local file2=$2

  ../client/ct consistency --ct_server="$SERVER" --ct_server_port=$PORT \
    --ct_server_public_key=$CT_KEY --logtostderr=true $HTTP_LOG \
    --sth1=$file1 --sth2=$file2
}

get_sth $CERT_DIR/sth1

make_cert $CERT_DIR test ca $SERVER $PORT false $CT_KEY
make_embedded_cert $CERT_DIR test-embedded ca $SERVER $PORT false \
    false $CT_KEY

# Do the audits together, quicker that way.
# test-*-cert.ctdata is made by make_cert.
do_audit $CERT_DIR/test-cert.ctdata
do_audit $CERT_DIR/test-embedded-cert.ctdata

get_sth $CERT_DIR/sth2

consistency $CERT_DIR/sth1 $CERT_DIR/sth2

echo $PASSED passed
echo $FAILED failed
