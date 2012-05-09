make_ca_certs() {
  cert_dir=$1
  ca=$2
  openssl req -x509 -newkey rsa:1024 -keyout $cert_dir/$ca-key.pem \
    -out $cert_dir/$ca-cert.pem -config ca-cert.conf -passout pass:password1

  openssl req -newkey rsa:1024 -keyout $cert_dir/$ca-protokey.pem \
    -out $cert_dir/$ca-protocert.csr -config ca-protocert.conf \
    -passout pass:password1

  openssl x509 -req -days 365 -in $cert_dir/$ca-protocert.csr \
    -CA $cert_dir/$ca-cert.pem -CAkey $cert_dir/$ca-key.pem -CAcreateserial \
    -CAserial $cert_dir/$ca-cert.srl -extfile ca-protocert.conf \
    -extensions ct_ext -out $cert_dir/$ca-protocert.pem -passin pass:password1
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
  server=$2
  ca=$3
  log_server=$4

  # Generate a new private key and CSR
  openssl req -new -newkey rsa:1024 -keyout $cert_dir/$server-key-pw.pem \
    -out $cert_dir/$server-cert.csr -config protocert.conf \
    -passout pass:password1

  openssl rsa -in $cert_dir/$server-key-pw.pem -out $cert_dir/$server-key.pem \
    -passin pass:password1

  # Sign the CSR with the CA key
  openssl x509 -req -days 365 -in $cert_dir/$server-cert.csr \
    -CA $cert_dir/$ca-cert.pem -CAkey $cert_dir/$ca-key.pem -CAcreateserial \
    -CAserial $cert_dir/$ca-cert.srl -extfile protocert.conf \
    -extensions simple -passin pass:password1 -out $cert_dir/$server-cert.pem

  openssl x509 -in $cert_dir/$server-cert.pem -out $cert_dir/$server-cert.der \
    -outform DER

  # Make a protocert and sign with the CA protocert key
  ../client/ct protocert $cert_dir/$server-cert.csr \
    $cert_dir/$server-protocert.der $cert_dir/$ca-protocert.pem \
    $cert_dir/$ca-protokey.pem password1 $cert_dir/$ca-cert.pem protocert.conf

  # Start the log server and wait for it to come up
  ../server/ct-server 8124 $cert_dir/$log_server-key.pem 1 1 &
  server_pid=$!
  sleep 2

  # Upload the signed certificate
  ../client/ct upload $cert_dir/$server-cert.der 127.0.0.1 8124 -server_key \
    $cert_dir/$log_server-key-public.pem
  ../client/ct upload $cert_dir/$server-cert.der 127.0.0.1 8124 -server_key \
    $cert_dir/$log_server-key-public.pem -out $cert_dir/$server-cert.proof

  # Upload the protocert
  ../client/ct upload $cert_dir/$server-protocert.der 127.0.0.1 8124 \
    -server_key $cert_dir/$log_server-key-public.pem
  ../client/ct upload $cert_dir/$server-protocert.der 127.0.0.1 8124 \
    -server_key $cert_dir/$log_server-key-public.pem \
    -out $cert_dir/$server-protocert.proof

  # Create a superfluous certificate
  ../client/ct certificate $cert_dir/$server-cert.proof \
    $cert_dir/$server-cert-proof.der

  openssl x509 -in $cert_dir/$server-cert-proof.der -inform DER -out \
    $cert_dir/$server-cert-proof.pem

  # Create an embedded certificate
  ../client/ct sign $cert_dir/$server-protocert.der \
    $cert_dir/$server-protocert.proof  $cert_dir/$server-embedded-cert.pem \
    $cert_dir/$ca-key.pem password1

  # Stop the log server
  kill -9 $server_pid  
  sleep 2
}
