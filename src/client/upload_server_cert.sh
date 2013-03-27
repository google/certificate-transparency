#!/bin/sh

# Upload whatever cert the named server presents to the pilot log

set -e

SERVER=$1

TMP=`mktemp /tmp/cert.XXXXXX`

openssl s_client -connect $SERVER:443 -showcerts < /dev/null | tee $TMP

./ct --ct_server=ct.googleapis.com/pilot --http_log --logtostderr --ct_server_submission=$TMP upload

rm $TMP

