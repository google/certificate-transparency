# This generates a set of CMS signed wrapped DER format certs for use in unit
# testing.

set -e

TMP_REQ=/tmp/req.csr

create_cert() {
  config=$1
  sign_cert=$2
  sign_key=$3
  ext_section=$4
  out_file=$5

  rm -f $out_file

  openssl req -new -key testdata/ca-key.pem -out ${TMP_REQ} \
    -config $config -passin pass:password1
  openssl x509 -req -days 365 -in ${TMP_REQ} -CA ${sign_cert} \
    -CAkey ${sign_key} -passin pass:password1 -CAcreateserial \
    -out $out_file -outform DER -extfile $config -extensions $ext_section
} 

sign_cms() {
  in_file=$1
  sign_cert=$2
  sign_key=$3
  der_file=$4

  # -nocerts prevents the signing cert from being included and -nodetach
  # includes the message content in the output
  openssl cms -sign -outform PEM -signer $sign_cert \
    -inkey $sign_key -out $der_file -in $in_file \
    -passin pass:password1 -binary -nodetach -nocerts
}

make_cms_test_case_invalid_data() {
  test_name=$1
  cms_sign_cert=$2
  cms_sign_key=$3

  echo $1 ':'

  cat > /tmp/bad_payload <<EOF
THIS IS NOT VALID DER DATA
--------------------------
EOF

  sign_cms /tmp/bad_payload testdata/$cms_sign_cert \
    testdata/$cms_sign_key testdata/v2/cms_${test_name}.pem
}

make_cms_test_case() {
  test_name=$1
  cert_sign_cert=$2
  sign_key=$3
  cms_sign_cert=$4
  cms_sign_key=$5

  echo $1 ':'

  create_cert testdata/v2/configs/cms/${test_name}.config testdata/$cert_sign_cert \
    testdata/$sign_key $test_name /tmp/${test_name}.der
  sign_cms /tmp/${test_name}.der testdata/$cms_sign_cert \
    testdata/$cms_sign_key testdata/v2/cms_${test_name}.pem
}

# Generate the CMS test data

make_cms_test_case_invalid_data test2 ca-cert.pem ca-key.pem
make_cms_test_case test3 ca-cert.pem ca-key.pem ca-cert.pem ca-key.pem
make_cms_test_case test4 ca-cert.pem ca-key.pem intermediate-cert.pem \
  intermediate-key.pem
make_cms_test_case test5 intermediate-cert.pem intermediate-key.pem \
  intermediate-cert.pem intermediate-key.pem
