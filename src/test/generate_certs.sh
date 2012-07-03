make_ca_certs() {
  cert_dir=$1
  hash_dir=$2
  ca=$3
  my_openssl=$4

  if [ $my_openssl == "" ]; then
    my_openssl=openssl;
  fi

  # Create a serial and database files
  serial="$cert_dir/$ca-serial"
  database="$cert_dir/$ca-database"
  echo "0000000000000000" > $serial
  > $database
  > $database.attr

  # Create a CA config file from the default configuration
  # by setting the appropriate serial and database files.
  sed -e "s,default_serial,$serial," -e "s,default_database,$database," \
    default_ca.conf > $cert_dir/$ca.conf

  # Create a self-signed root certificate
  openssl req -new -newkey rsa:1024 -keyout $cert_dir/$ca-key.pem \
    -out $cert_dir/$ca-cert.csr -config ca-cert.conf -passout pass:password1

 echo -e "y\ny\n" | \
    openssl ca -in $cert_dir/$ca-cert.csr -selfsign \
    -keyfile $cert_dir/$ca-key.pem -config $cert_dir/$ca.conf \
    -extfile ca-cert.conf -extensions v3_ca -passin pass:password1 \
    -outdir $cert_dir -out $cert_dir/$ca-cert.pem

  # Put the root certificate in a trusted directory.
  # CT server will not understand the hash format for OpenSSL < 1.0.0
  echo "OpenSSL version is: "
  $my_openssl version
  hash=$($my_openssl x509 -in $cert_dir/$ca-cert.pem -hash -noout)
  cp $cert_dir/$ca-cert.pem $hash_dir/$hash.0

  # Create a CA protocert signing request.
  openssl req -newkey rsa:1024 -keyout $cert_dir/$ca-protokey.pem \
    -out $cert_dir/$ca-protocert.csr -config ca-protocert.conf \
    -passout pass:password1

  # Sign the CA protocert.
  echo -e "y\ny\n" | \
    openssl ca -in $cert_dir/$ca-protocert.csr -cert $cert_dir/$ca-cert.pem \
    -keyfile $cert_dir/$ca-key.pem -config $cert_dir/$ca.conf \
    -extfile ca-protocert.conf -extensions ct_ext -passin pass:password1 \
    -outdir $cert_dir -out $cert_dir/$ca-protocert.pem

  # Create a ProtoCA config file. The ProtoCA shall share the CA's serial file.
  # However, it needs a separate database, since we want to be able to issue
  # a cert with the same serial twice (once by the ProtoCA, once by the CA).
  protodatabase="$cert_dir/$ca-protodatabase"
  > $protodatabase
  > $protodatabase.attr

  sed  -e "s,default_serial,$serial," -e "s,default_database,$protodatabase," \
    default_ca.conf > $cert_dir/$ca-proto.conf
}

make_log_server_keys() {
  cert_dir=$1
  log_server=$2

  openssl ecparam -out $cert_dir/$log_server-key.pem -name secp256r1 -genkey

  openssl ec -in $cert_dir/$log_server-key.pem -pubout \
    -out $cert_dir/$log_server-key-public.pem
}

# Call make_ca_certs and make_log_server_keys first
make_certs() {
  cert_dir=$1
  hash_subdir=$2
  server=$3
  ca=$4
  log_server=$5

  # Generate a new private key and CSR
  openssl req -new -newkey rsa:1024 -keyout $cert_dir/$server-key-pw.pem \
    -out $cert_dir/$server-cert.csr -config protocert.conf \
    -passout pass:password1

  openssl rsa -in $cert_dir/$server-key-pw.pem -out $cert_dir/$server-key.pem \
    -passin pass:password1

  # Sign the CSR with the CA key
  echo -e "y\ny\n" | \
  openssl ca -in $cert_dir/$server-cert.csr -cert $cert_dir/$ca-cert.pem \
    -keyfile $cert_dir/$ca-key.pem -config $cert_dir/$ca.conf \
    -extfile protocert.conf -extensions simple -passin pass:password1 \
    -outdir $cert_dir -out $cert_dir/$server-cert.pem

  # Make a DER version
  openssl x509 -in $cert_dir/$server-cert.pem -out $cert_dir/$server-cert.der \
    -outform DER

  # Sign the CSR with the CA protocert key to get a log request
  echo -e "y\ny\n" | \
  openssl ca -in $cert_dir/$server-cert.csr -cert $cert_dir/$ca-protocert.pem \
    -keyfile $cert_dir/$ca-protokey.pem -config $cert_dir/$ca-proto.conf \
    -extfile protocert.conf -extensions proto -passin pass:password1 \
    -outdir $cert_dir -out $cert_dir/$server-protocert.pem

  # Start the log server and wait for it to come up
echo "Starting CT server with trusted certs in $hash_dir"
  ../server/ct-server 8124 $cert_dir/$log_server-key.pem 1 1 $hash_dir &
  server_pid=$!
  sleep 2

  # Upload the signed certificate
  ../client/ct upload $cert_dir/$server-cert.pem 127.0.0.1 8124 -server_key \
    $cert_dir/$log_server-key-public.pem
  ../client/ct upload $cert_dir/$server-cert.pem 127.0.0.1 8124 -server_key \
    $cert_dir/$log_server-key-public.pem -out $cert_dir/$server-cert.proof

  # Upload the protocert bundle
  cat $cert_dir/$server-protocert.pem $cert_dir/$ca-protocert.pem > \
     $cert_dir/$server-protocert-bundle.pem
  ../client/ct upload $cert_dir/$server-protocert-bundle.pem 127.0.0.1 8124 \
    -server_key $cert_dir/$log_server-key-public.pem -proto
  ../client/ct upload $cert_dir/$server-protocert-bundle.pem 127.0.0.1 8124 \
    -server_key $cert_dir/$log_server-key-public.pem \
    -out $cert_dir/$server-protocert.proof -proto
  rm $cert_dir/$server-protocert-bundle.pem

  # Create a superfluous certificate
  ../client/ct certificate $cert_dir/$server-cert.proof \
    $cert_dir/$server-cert-proof.der

  openssl x509 -in $cert_dir/$server-cert-proof.der -inform DER -out \
    $cert_dir/$server-cert-proof.pem

  # Create a new extensions config with the embedded proof
  cp protocert.conf $cert_dir/$server-extensions.conf
  ../client/ct configure_proof $cert_dir/$server-extensions.conf \
    $cert_dir/$server-protocert.proof 
  # Sign the certificate
  # Store the current serial number
  mv $cert_dir/$ca-serial $cert_dir/$ca-serial.bak
  # Instead reuse the serial number from the protocert
  openssl x509 -in $cert_dir/$server-protocert.pem -serial -noout | \
    sed 's/serial=//' > $cert_dir/$ca-serial
  echo -e "y\ny\n" | \
    openssl ca -in $cert_dir/$server-cert.csr -cert $cert_dir/$ca-cert.pem \
    -keyfile $cert_dir/$ca-key.pem -config $cert_dir/$ca.conf \
    -extfile $cert_dir/$server-extensions.conf -extensions embedded \
    -passin pass:password1 -outdir $cert_dir \
    -out $cert_dir/$server-embedded-cert.pem
  # Restore the serial number
  mv $cert_dir/$ca-serial.bak $cert_dir/$ca-serial

  # Stop the log server
  kill -9 $server_pid  
  sleep 2
}
