#!/bin/sh

# Upload whatever cert the named server presents to the pilot log

set -e

export PYTHONPATH=$(PYTHONPATH):../python
SERVER=$1

TMP=`mktemp /tmp/cert.XXXXXX`

openssl s_client -connect $SERVER:443 -showcerts < /dev/null | tee $TMP

if ./ct --ct_server=ct.googleapis.com/pilot --http_log --logtostderr --ct_server_submission=$TMP upload
then
    echo Done
else
    echo Try fixing the chain
    TMP2=`mktemp /tmp/cert.XXXXXX`
    ./fix-chain.py $TMP | tee $TMP2
    ./ct --ct_server=ct.googleapis.com/pilot --http_log --logtostderr --ct_server_submission=$TMP2 upload
    rm $TMP2
fi

rm $TMP

