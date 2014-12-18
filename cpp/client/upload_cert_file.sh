#!/bin/sh

# Upload certificate from file to CT log

set -e
upload() {
    if [ -n "$CHAIN_FIXED" ]; then
    TMP=$TMP2
    fi
    ./ct upload --ct_server=$CT_SERVER --logtostderr --ct_server_submission=$TMP --ct_server_public_key=$PUBKEY --precert=$PRECERT
}
export PYTHONPATH=${PYTHONPATH}:../python
if [[ $# -eq 0 ]] ; then
    echo "USAGE: $0 [cert] [log pubkey] [precert?] (ct server address)"
    exit 1
fi
FILE=$1 # file to upload
PUBKEY=$2 # PEM encoded public key
PRECERT=$3 # true or false
#CT_SERVER='ct.googleapis.com/pilot'
if [ -z "$4" ]; then
CT_SERVER='localhost:8888'
else
CT_SERVER=$4
fi
TMP=`mktemp /tmp/cert.XXXXXX`

cp $FILE $TMP
if upload
then
    echo Done
    rm $TMP
else
    echo Try fixing the chain
    TMP2=`mktemp /tmp/cert.XXXXXX`
    ./fix-chain.py $TMP | tee $TMP2
    CHAIN_FIXED=1
    upload
    rm $TMP
    rm $TMP2
fi

