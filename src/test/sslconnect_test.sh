#!/bin/bash

# Note: run make freebsd-links or make linux-links before running this test

source generate_certs.sh

PASSED=0
FAILED=0

test_connect() {
  cert_dir=$1
  log_server=$2
  ca=$3
  port=$4
  expected_retcode=$5

  ../client/ct connect 127.0.0.1 $port -log_server_key \
	$cert_dir/$log_server-key-public.pem -ca_file $cert_dir/$ca-cert.pem
  local retcode=$?

  if [ $retcode -eq $expected_retcode ]; then
    echo "PASS"
    let PASSED=$PASSED+1
  else
    echo "FAIL"
    let FAILED=$FAILED+1
  fi
}

test_range() {
  ports=$1
  cert_dir=$2
  log_server=$3
  ca=$4
  conf=$5
  retcode=$6

  # Tell Apache where to find mod_ssl by copying the symlink in test
  if [ ! -f $cert_dir/mod_ssl.so ]; then
    cp mod_ssl.so $cert_dir/mod_ssl.so
  fi

  echo "Starting Apache"
  ./apachectl -d `pwd`/$cert_dir -f `pwd`/$conf -k start

  echo "Testing valid configurations"
  for port in $ports; do
    test_connect $cert_dir $log_server $ca $port $retcode;
  done

  echo "Stopping Apache"
  ./apachectl -d `pwd`/$cert_dir -f `pwd`/httpd-valid.conf -k stop
  # Wait for Apache to die
  sleep 5

}

test_valid_range() {
  # Valid ranges from httpd-valid.conf
  ports="8125 8126 8127 8128"
  cert_dir=$1
  log_server=$2
  ca=$3
  conf="httpd-valid.conf"

  test_range "$ports" $cert_dir $log_server $ca $conf 0
}

test_invalid_range() {
  # Inalid ranges from httpd-invalid.conf
  ports="8125 8126 8127 8128 8129"
  cert_dir=$1
  log_server=$2
  ca=$3
  conf="httpd-invalid.conf"

  test_range "$ports" $cert_dir $log_server $ca $conf 2
}

# Regression tests against known good/bad certificates
test_valid_range testdata ct-server ca
test_invalid_range testdata ct-server ca

# Generate new certs dynamically and repeat the test for valid certs
mkdir -p tmp
echo "Generating CA certificates in tmp" 
make_ca_certs tmp ca
echo "Generating log server keys in tmp"
make_log_server_keys tmp ct-server
echo "Generating test certificates"
make_certs tmp test ca ct-server
# Note: this will start the log server twice and thus generate an inconsistent
# log view; however, our client is stateless and won't notice
# TODO: add cache tests for detecting inconsistencies.
make_certs tmp test2 ca ct-server

echo "Testing valid configurations with new certificates" 
test_valid_range tmp ct-server ca
echo "Cleaning up"
rm -rf tmp
echo "PASSED $PASSED tests"
echo "FAILED $FAILED tests"
