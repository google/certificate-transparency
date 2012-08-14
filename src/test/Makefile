test-cert.authz: test-cert.proof
	../client/ct authz test-cert.proof test-cert.authz

run-test-apache: test-cert.authz
	LD_LIBRARY_PATH=../../../../work/openssl-1.0.2 ../../../../svn-work/httpd/httpd -d `pwd` -f `pwd`/httpd2.conf

freebsd-links:
	ln -sf `which apachectl` apachectl
	ln -sf /usr/local/libexec/apache22/mod_ssl.so mod_ssl.so

linux-links:
	ln -sf `which apache2ctl` apachectl
	ln -sf /usr/lib/apache2/modules/mod_ssl.so mod_ssl.so
