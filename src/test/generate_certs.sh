set -e

ca_setup() {
  cert_dir=$1
  ca=$2
  pre=$3

  # Create serial and database files.
  serial="$cert_dir/$ca-serial"
  # The PreCA shall share the CA's serial file.
  # However, it needs a separate database, since we want to be able to issue
  # a cert with the same serial twice (once by the PreCA, once by the CA).
  if [ $pre == "true" ]; then
    database="$cert_dir/$ca-pre-database"
    conf=$ca-pre
  else
    database="$cert_dir/$ca-database"
    conf=$ca
    echo "0000000000000000" > $serial
  fi

  > $database
  > $database.attr

  # Create a CA config file from the default configuration
  # by setting the appropriate serial and database files.
  sed -e "s,default_serial,$serial," -e "s,default_database,$database," \
    default_ca.conf > $cert_dir/$conf.conf
}

request_cert() {
  cert_dir=$1
  subject=$2
  config=$3

  openssl req -new -newkey rsa:1024 -keyout $cert_dir/$subject-key.pem \
    -out $cert_dir/$subject-cert.csr -config $config -passout pass:password1
}

issue_cert() {
cert_dir=$1
issuer=$2
subject=$3
extfile=$4
extensions=$5
selfsign=$6
out=$7

if [ $selfsign == "true" ]; then
  cert_args="-selfsign"
else
  cert_args="-cert $cert_dir/$issuer-cert.pem"
fi

 echo -e "y\ny\n" | \
    openssl ca -in $cert_dir/$subject-cert.csr $cert_args \
    -keyfile $cert_dir/$issuer-key.pem -config $cert_dir/$issuer.conf \
    -extfile $extfile -extensions $extensions -passin pass:password1 \
    -outdir $cert_dir -out $cert_dir/$out-cert.pem
}

make_ca_certs() {
  cert_dir=$1
  hash_dir=$2
  ca=$3
  my_openssl=$4

  if [ $my_openssl == "" ]; then
    my_openssl=openssl;
  fi

  # Setup root CA database and files
  ca_setup $cert_dir $ca false

  # Create a self-signed root certificate
  request_cert $cert_dir $ca ca-cert.conf
  issue_cert $cert_dir $ca $ca ca-cert.conf v3_ca true $ca

  # Put the root certificate in a trusted directory.
  # CT server will not understand the hash format for OpenSSL < 1.0.0
  echo "OpenSSL version is: "
  $my_openssl version
  hash=$($my_openssl x509 -in $cert_dir/$ca-cert.pem -hash -noout)
  cp $cert_dir/$ca-cert.pem $hash_dir/$hash.0

  # Create a CA precert signing request.
  request_cert $cert_dir $ca-pre ca-precert.conf
  # Sign the CA precert.
  issue_cert $cert_dir $ca $ca-pre ca-precert.conf ct_ext false $ca-pre
  ca_setup $cert_dir $ca true
}

make_log_server_keys() {
  cert_dir=$1
  log_server=$2

  openssl ecparam -out $cert_dir/$log_server-key.pem -name secp256r1 -genkey

  openssl ec -in $cert_dir/$log_server-key.pem -pubout \
    -out $cert_dir/$log_server-key-public.pem
}

make_intermediate_ca_certs() {
  cert_dir=$1
  intermediate=$2
  ca=$3

  # Issue an intermediate CA certificate
  request_cert $cert_dir $intermediate intermediate-ca-cert.conf
  issue_cert $cert_dir $ca $intermediate ca-cert.conf v3_ca false $intermediate

  # Setup a database for the intermediate CA
  ca_setup $cert_dir $intermediate false

  # Issue a precert signing cert
  request_cert $cert_dir $intermediate-pre intermediate-ca-precert.conf
  issue_cert $cert_dir $intermediate $intermediate-pre \
    intermediate-ca-precert.conf ct_ext false $intermediate-pre

  ca_setup $cert_dir $intermediate true
}

# Call make_ca_certs and make_log_server_keys first
make_cert() {
  local cert_dir=$1
  local server=$2
  local ca=$3
  local log_server_name=$4
  local log_server=$5
  local log_server_port=$6
  local ca_is_intermediate=$7
  local server_public_key=$8

  # Generate a new private key and CSR
  request_cert $cert_dir $server precert.conf

  openssl rsa -in $cert_dir/$server-key.pem -out $cert_dir/$server-key.pem \
    -passin pass:password1

  # Sign the CSR with the CA key
  issue_cert $cert_dir $ca $server precert.conf simple false $server

  # Make a DER version
  openssl x509 -in $cert_dir/$server-cert.pem -out $cert_dir/$server-cert.der \
    -outform DER

  # Upload the signed certificate
  # If the CA is an intermediate, then we need to include its certificate, too.
  if [ $ca_is_intermediate == "true" ]; then
    cat $cert_dir/$server-cert.pem $cert_dir/$ca-cert.pem > \
      $cert_dir/$server-cert-bundle.pem
  else
    cat $cert_dir/$server-cert.pem > $cert_dir/$server-cert-bundle.pem
  fi

  echo ../client/ct upload \
    --ct_server_submission=$cert_dir/$server-cert-bundle.pem \
    --ct_server=$log_server --ct_server_port=$log_server_port \
    --ct_server_public_key=$server_public_key \
    --ct_server_response_out=$cert_dir/$server-cert.proof \
    --logtostderr=true $HTTP_LOG
  ../client/ct upload \
    --ct_server_submission=$cert_dir/$server-cert-bundle.pem \
    --ct_server=$log_server --ct_server_port=$log_server_port \
    --ct_server_public_key=$server_public_key \
    --ct_server_response_out=$cert_dir/$server-cert.proof \
    --logtostderr=true $HTTP_LOG

  # Create a wrapped SCT
  ../client/ct wrap --alsologtostderr \
    --sct_in=$cert_dir/$server-cert.proof \
    --certificate_chain_in=$cert_dir/$server-cert-bundle.pem \
    --ct_server_public_key=$server_public_key \
    --ssl_client_ct_data_out=$cert_dir/$server-cert.ctdata

  rm $cert_dir/$server-cert-bundle.pem

  # Create a superfluous certificate
  ../client/ct certificate --sct_token=$cert_dir/$server-cert.proof \
    --certificate_out=$cert_dir/$server-cert-proof.der \
    --logtostderr=true

  openssl x509 -in $cert_dir/$server-cert-proof.der -inform DER -out \
    $cert_dir/$server-cert-proof.pem

  # If the CA is an intermediate, create a single chain file
  if [ $ca_is_intermediate == "true" ]; then
    cat $cert_dir/$ca-cert.pem $cert_dir/$server-cert-proof.pem > \
      $cert_dir/$server-cert-chain.pem
  else
    cat $cert_dir/$server-cert-proof.pem > $cert_dir/$server-cert-chain.pem
  fi
}

# Call make_ca_certs and make_log_server_keys first
make_embedded_cert() {
  local cert_dir=$1
  local server=$2
  local ca=$3
  local log_server=$4
  local log_server_name=$5
  local log_server_port=$6
  local ca_is_intermediate=$7
  local use_pre_ca=$8
  local server_public_key=$9

  # Generate a new private key and CSR
  request_cert $cert_dir $server precert.conf

  openssl rsa -in $cert_dir/$server-key.pem -out $cert_dir/$server-key.pem \
    -passin pass:password1

  # Sign the CSR to get a log request
  if [ $use_pre_ca == "true" ]; then
    issue_cert $cert_dir $ca-pre $server precert.conf pre false $server-pre
  else
  # Issue a precert, but since it's not real, do not update the database.
    cp $cert_dir/$ca-database $cert_dir/$ca-database.bak
    issue_cert $cert_dir $ca $server precert.conf pre false $server-pre
    mv $cert_dir/$ca-database.bak $cert_dir/$ca-database
  fi

  # Upload the precert bundle
  # If we're using a Precert Signing CA then we need to send it along
  if [ $use_pre_ca == "true" ]; then
    cat $cert_dir/$server-pre-cert.pem $cert_dir/$ca-pre-cert.pem > \
      $cert_dir/$server-precert-tmp.pem
  else
    cat $cert_dir/$server-pre-cert.pem > $cert_dir/$server-precert-tmp.pem
  fi

  # If the CA is an intermediate, then we need to include its certificate, too.
  if [ $ca_is_intermediate == "true" ]; then
    cat $cert_dir/$server-precert-tmp.pem $cert_dir/$ca-cert.pem > \
      $cert_dir/$server-precert-bundle.pem
  else
    cat $cert_dir/$server-precert-tmp.pem > \
      $cert_dir/$server-precert-bundle.pem
  fi

  ../client/ct upload \
    --ct_server_submission=$cert_dir/$server-precert-bundle.pem \
    --ct_server=$log_server_name --ct_server_port=$log_server_port \
    --ct_server_public_key=$cert_dir/$log_server-key-public.pem \
    --ct_server_response_out=$cert_dir/$server-pre-cert.proof \
    --precert=true --logtostderr=true $HTTP_LOG
  rm $cert_dir/$server-precert-tmp.pem
  rm $cert_dir/$server-precert-bundle.pem

  # Create a new extensions config with the embedded proof
  cp precert.conf $cert_dir/$server-extensions.conf
  ../client/ct configure_proof \
    --extensions_config_out=$cert_dir/$server-extensions.conf \
    --sct_token=$cert_dir/$server-pre-cert.proof --logtostderr=true 
  # Sign the certificate
  # Store the current serial number
  mv $cert_dir/$ca-serial $cert_dir/$ca-serial.bak
  # Instead reuse the serial number from the precert
  openssl x509 -in $cert_dir/$server-pre-cert.pem -serial -noout | \
    sed 's/serial=//' > $cert_dir/$ca-serial

  issue_cert $cert_dir $ca $server $cert_dir/$server-extensions.conf embedded \
    false $server

  # Create a wrapped SCT
  cp $cert_dir/$server-cert.pem $cert_dir/$server-cert-bundle.pem
  # If the CA is an intermediate, then we need to include its
  # certificate, too.  We also need the CA certificate (kludge alert,
  # we happen to know which one that is, so hardwire).
  if [ $ca_is_intermediate == "true" ]; then
    cat $cert_dir/$ca-cert.pem $cert_dir/ca-cert.pem \
	>> $cert_dir/$server-cert-bundle.pem
  else
    cat $cert_dir/$ca-cert.pem >> $cert_dir/$server-cert-bundle.pem
  fi
  ../client/ct wrap_embedded --alsologtostderr \
    --certificate_chain_in=$cert_dir/$server-cert-bundle.pem \
    --ct_server_public_key=$server_public_key \
    --ssl_client_ct_data_out=$cert_dir/$server-cert.ctdata

  # Restore the serial number
  mv $cert_dir/$ca-serial.bak $cert_dir/$ca-serial
}
