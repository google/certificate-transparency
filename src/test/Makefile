all: test-cert-proof.pem

# Generate a self-signed root CA certificate and private key file
ca-cert.pem:
	openssl req -x509 -newkey rsa:1024 -keyout ca-key.pem -out ca-cert.pem \
	-config ca-cert.conf -passout pass:password1

# Generate a certificate for signing log requests
ca-protocert.pem: ca-cert.pem
	openssl req -newkey rsa:1024 -keyout ca-protokey.pem \
	-out ca-protocert.csr -config ca-protocert.conf -passout pass:password1
	openssl x509 -req -days 365 -in ca-protocert.csr -CA ca-cert.pem \
	-CAkey ca-key.pem -CAcreateserial -extfile ca-protocert.conf \
	-extensions ct_ext -out ca-protocert.pem -passin pass:password1

test-cert.csr:
	openssl req -new -newkey rsa:1024 -keyout test-key.pem \
	-out test-cert.csr -config protocert.conf -passout pass:password1

# Generate a protocert for submitting to the log
test-protocert.der: ca-protocert.pem test-cert.csr
	../client/ct protocert test-cert.csr test-protocert.der \
	ca-protocert.pem ca-protokey.pem password1 ca-cert.pem protocert.conf

test-cert.pem: test-cert.csr
	openssl x509 -req -days 365 -in test-cert.csr -signkey test-key.pem \
	-out test-cert.pem

test-cert.der: test-cert.pem
	openssl x509 -in test-cert.pem -out test-cert.der -outform DER

test-cert.proof: test-cert.der ct-server-key-public.pem
	../client/ct upload test-cert.der 127.0.0.1 8124 -server_key \
	ct-server-key-public.pem -out test-cert.proof

test-cert-proof.der: test-cert.proof
	../client/ct certificate test-cert.proof test-cert-proof.der

test-cert-proof.pem: test-cert-proof.der
	openssl x509 -in test-cert-proof.der -inform DER -out \
	test-cert-proof.pem

ct-server-key.pem:
	openssl ecparam -out ct-server-key.pem -name secp256r1  -genkey

ct-server-key-public.pem: ct-server-key.pem
	openssl ec -in ct-server-key.pem -pubout -out ct-server-key-public.pem

run-server: ct-server-key.pem
	../server/ct-server 8124 ct-server-key.pem 1 1

run-apache: test-cert.pem test-key.pem test-cert-proof.pem
	./apachectl -d `pwd` -f `pwd`/httpd.conf -k start

restart-apache:
	./apachectl -d `pwd` -f `pwd`/httpd.conf -k restart

stop-apache:
	./apachectl -d `pwd` -f `pwd`/httpd.conf -k stop

connect: ct-server-key-public.pem
	mkdir -p .cache
	../client/ct connect 127.0.0.1 8123 -log_server_key \
	ct-server-key-public.pem -cache .cache

clean:
	rm -f *.pem *.der *.csr *.proof *.srl
	rm -rf .cache

freebsd-links:
	ln -sf `which apachectl` apachectl
	ln -sf /usr/local/libexec/apache22/mod_ssl.so mod_ssl.so

linux-links:
	ln -sf `which apache2ctl` apachectl
	ln -sf /usr/lib/apache2/modules/mod_ssl.so mod_ssl.so
