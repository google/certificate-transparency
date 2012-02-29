all: test-cert-proof.pem

test-key.pem:
	openssl genrsa -out test-key.pem 1024

test-cert.csr: test-key.pem
	openssl req -new -key test-key.pem -out test-cert.csr < test-csr-responses

test-cert.pem: test-cert.csr
	openssl x509 -req -days 365 -in test-cert.csr -signkey test-key.pem -out test-cert.pem

test-cert.der: test-cert.pem
	openssl x509 -in test-cert.pem -out test-cert.der -outform DER

test-cert.proof: test-cert.der ct-server-key-public.pem
	../client/ct upload test-cert.der 127.0.0.1 8124 ct-server-key-public.pem test-cert.proof

test-cert-proof.der: test-cert.proof
	../client/ct certificate test-cert.proof test-cert-proof.der

test-cert-proof.pem: test-cert-proof.der
	openssl x509 -in test-cert-proof.der -inform DER -out test-cert-proof.pem

ct-server-key.pem:
	openssl ecparam -out ct-server-key.pem -name secp256r1  -genkey

ct-server-key-public.pem: ct-server-key.pem
	openssl ec -in ct-server-key.pem -pubout -out ct-server-key-public.pem

run-server: ct-server-key.pem
	../server/ct-server 8124 ct-server-key.pem 1 1

run-apache: test-cert.pem test-key.pem test-cert-proof.pem
	apache2ctl -d `pwd` -f `pwd`/httpd.conf -k start

restart-apache:
	apache2ctl -d `pwd` -f `pwd`/httpd.conf -k restart

stop-apache:
	apache2ctl -d `pwd` -f `pwd`/httpd.conf -k stop

connect: ct-server-key-public.pem
	../client/ct connect 127.0.0.1 8123 ct-server-key-public.pem 

clean:
	rm -f test-key.* test-cert.* test-cert-proof.* ct-server-key.* ct-server-key-public.*

