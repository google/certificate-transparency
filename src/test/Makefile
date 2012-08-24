freebsd-links:
	ln -sf `which apachectl` apachectl
	ln -sf /usr/local/libexec/apache22/mod_ssl.so mod_ssl.so

linux-links:
	ln -sf `which apache2ctl` apachectl
	ln -sf /usr/lib/apache2/modules/mod_ssl.so mod_ssl.so

# Optionally point to a (local) Apache HEAD (or patched 2.4/2.2) build 
# with Authz control.
local-links:
	ln -sf $(APACHEDIR)/httpd httpd-new
	ln -sf $(APACHEDIR)/modules/ssl/.libs/mod_ssl.so mod_ssl_new.so
	ln -sf $(APACHEDIR)/modules/arch/unix/.libs/mod_unixd.so \
	mod_unixd_new.so

test:
	cd ../client && $(MAKE)
	cd ../server && $(MAKE)
	OPENSSLDIR=$(OPENSSLDIR) ./sslconnect_test.sh
