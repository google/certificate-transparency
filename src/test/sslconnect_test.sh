#!/bin/bash

# Note: run make freebsd-links or make linux-links before running this test

source generate_certs.sh

PASSED=0
FAILED=0

if [ $MY_OPENSSL == "" ]; then
# Try to use the system OpenSSL
  MY_OPENSSL=openssl
fi

test_connect() {
  cert_dir=$1
  hash_dir=$2
  log_server=$3
  ca=$4
  port=$5
  expected_retcode=$6

  ../client/ct connect 127.0.0.1 $port -log_server_key \
	$cert_dir/$log_server-key-public.pem -ca_dir $hash_dir
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
  hash_dir=$3
  log_server=$4
  ca=$5
  conf=$6
  retcode=$7

  # Tell Apache where to find mod_ssl by copying the symlink in test
  if [ ! -f $cert_dir/mod_ssl.so ]; then
    cp mod_ssl.so $cert_dir/mod_ssl.so
  fi

  echo "Starting Apache"
  ./apachectl -d `pwd`/$cert_dir -f `pwd`/$conf -k start

  echo "Testing valid configurations"
  for port in $ports; do
    test_connect $cert_dir $hash_dir $log_server $ca $port $retcode;
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
  hash_dir=$2
  log_server=$3
  ca=$4
  conf="httpd-valid.conf"

  test_range "$ports" $cert_dir $hash_dir $log_server $ca $conf 0
}

test_invalid_range() {
  # Inalid ranges from httpd-invalid.conf
  ports="8125 8126 8127 8128 8129"
  cert_dir=$1
  hash_dir=$2
  log_server=$3
  ca=$4
  conf="httpd-invalid.conf"

  test_range "$ports" $cert_dir $hash_dir $log_server $ca $conf 2
}

# Regression tests against known good/bad certificates
mkdir -p ca-hashes
hash=$($MY_OPENSSL x509 -in testdata/ca-cert.pem -hash -noout)
cp testdata/ca-cert.pem ca-hashes/$hash.0

test_valid_range testdata ca-hashes ct-server ca
test_invalid_range testdata ca-hashes ct-server ca

rm -rf ca-hashes

# Generate new certs dynamically and repeat the test for valid certs
mkdir -p tmp
# A directory for trusted certs in OpenSSL "hash format"
mkdir -p tmp/ca-hashes
echo "Generating CA certificates in tmp and hashes in tmp/ca"
make_ca_certs `pwd`/tmp `pwd`/tmp/ca-hashes ca $MY_OPENSSL
echo "Generating log server keys in tmp"
make_log_server_keys `pwd`/tmp ct-server
echo "Generating test certificates"
# TODO: also make a set of certs that chain through an intermediate
make_certs `pwd`/tmp `pwd`/tmp/ca-hashes test ca ct-server
# Note: this will start the log server twice and thus generate an inconsistent
# log view; however, our client is stateless and won't notice
# TODO: add cache tests for detecting inconsistencies.
make_certs `pwd`/tmp `pwd`/tmp/ca-hashes test2 ca ct-server

echo "Testing valid configurations with new certificates" 
test_valid_range tmp tmp/ca-hashes ct-server ca
echo "Cleaning up"
rm -rf tmp
echo "PASSED $PASSED tests"
echo "FAILED $FAILED tests"
