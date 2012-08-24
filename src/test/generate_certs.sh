set -e

ca_setup() {
  cert_dir=$1
  ca=$2
  proto=$3

  # Create serial and database files.
  serial="$cert_dir/$ca-serial"
  # The ProtoCA shall share the CA's serial file.
  # However, it needs a separate database, since we want to be able to issue
  # a cert with the same serial twice (once by the ProtoCA, once by the CA).
  if [ $proto == "true" ]; then
    database="$cert_dir/$ca-proto-database"
    conf=$ca-proto
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

  # Create a CA protocert signing request.
  request_cert $cert_dir $ca-proto ca-protocert.conf
  # Sign the CA protocert.
  issue_cert $cert_dir $ca $ca-proto ca-protocert.conf ct_ext false $ca-proto
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

  # Issue a protocert signing cert
  request_cert $cert_dir $intermediate-proto intermediate-ca-protocert.conf
  issue_cert $cert_dir $intermediate $intermediate-proto \
    intermediate-ca-protocert.conf ct_ext false $intermediate-proto

  ca_setup $cert_dir $intermediate true
}

# Call make_ca_certs and make_log_server_keys first
make_certs() {
  cert_dir=$1
  hash_dir=$2
  server=$3
  ca=$4
  log_server=$5
  log_server_port=$6
  ca_is_intermediate=$7

  # Generate a new private key and CSR
  request_cert $cert_dir $server protocert.conf

  openssl rsa -in $cert_dir/$server-key.pem -out $cert_dir/$server-key.pem \
    -passin pass:password1

  # Sign the CSR with the CA key
  issue_cert $cert_dir $ca $server protocert.conf simple false $server

  # Make a DER version
  openssl x509 -in $cert_dir/$server-cert.pem -out $cert_dir/$server-cert.der \
    -outform DER

  # Sign the CSR with the CA protocert key to get a log request
  issue_cert $cert_dir $ca-proto $server protocert.conf proto false $server-proto

  # Upload the signed certificate
  # If the CA is an intermediate, then we need to include its certificate, too.
  if [ $ca_is_intermediate == "true" ]; then
    cat $cert_dir/$server-cert.pem $cert_dir/$ca-cert.pem > \
      $cert_dir/$server-cert-bundle.pem
  else
    cat $cert_dir/$server-cert.pem > $cert_dir/$server-cert-bundle.pem
  fi

  ../client/ct upload $cert_dir/$server-cert-bundle.pem 127.0.0.1 \
    $log_server_port -server_key $cert_dir/$log_server-key-public.pem \
    -out $cert_dir/$server-cert.proof
  rm $cert_dir/$server-cert-bundle.pem

  # Upload the protocert bundle
  # If the CA is an intermediate, then we need to include its certificate, too.
  if [ $ca_is_intermediate == "true" ]; then
    cat $cert_dir/$server-proto-cert.pem $cert_dir/$ca-proto-cert.pem \
      $cert_dir/$ca-cert.pem > $cert_dir/$server-protocert-bundle.pem
  else
    cat $cert_dir/$server-proto-cert.pem $cert_dir/$ca-proto-cert.pem > \
      $cert_dir/$server-protocert-bundle.pem
  fi

  ../client/ct upload $cert_dir/$server-protocert-bundle.pem 127.0.0.1 \
    $log_server_port -server_key $cert_dir/$log_server-key-public.pem \
    -out $cert_dir/$server-proto-cert.proof -proto
  rm $cert_dir/$server-protocert-bundle.pem

  # Create a superfluous certificate
  ../client/ct certificate $cert_dir/$server-cert.proof \
    $cert_dir/$server-cert-proof.der

  openssl x509 -in $cert_dir/$server-cert-proof.der -inform DER -out \
    $cert_dir/$server-cert-proof.pem

# If the CA is an intermediate, create a single chain file
  if [ $ca_is_intermediate == "true" ]; then
    cat $cert_dir/$ca-cert.pem $cert_dir/$server-cert-proof.pem > \
      $cert_dir/$server-cert-chain.pem
  fi

  # Create a new extensions config with the embedded proof
  cp protocert.conf $cert_dir/$server-extensions.conf
  ../client/ct configure_proof $cert_dir/$server-extensions.conf \
    $cert_dir/$server-proto-cert.proof 
  # Sign the certificate
  # Store the current serial number
  mv $cert_dir/$ca-serial $cert_dir/$ca-serial.bak
  # Instead reuse the serial number from the protocert
  openssl x509 -in $cert_dir/$server-proto-cert.pem -serial -noout | \
    sed 's/serial=//' > $cert_dir/$ca-serial

  issue_cert $cert_dir $ca $server $cert_dir/$server-extensions.conf embedded \
    false $server-embedded

  # Restore the serial number
  mv $cert_dir/$ca-serial.bak $cert_dir/$ca-serial
}
