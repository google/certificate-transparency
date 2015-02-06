
# Make sure this is always first.
.PHONY: default
default: all

-include local.mk

CXXFLAG = -std=c++11 -Wall -Werror -g -O3
LINK.o = $(LINK.cc)

INCLUDE = -I .
LOCAL_LIBS = log/libcert.a log/libcluster.a log/libdatabase.a \
             log/liblog.a merkletree/libmerkletree.a \
             proto/libproto.a util/libutil.a
LDLIBS = -lpthread -lgflags -lglog -lssl -lcrypto -lldns -lsqlite3 \
         -lprotobuf -levent_core -levent_extra -levent_pthreads

PLATFORM := $(shell uname -s)
ifeq ($(PLATFORM), FreeBSD)
  LDLIBS += -L/usr/local/lib/event2
else
  LDLIBS += -lresolv
endif

# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE += -I $(OPENSSLDIR)/include
  LDLIBS += -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -Wl,-rpath,$(OPENSSLDIR) \
            -Wl,-rpath,$(OPENSSLDIR)/lib
endif

# Need libevent
ifneq ($(LIBEVENTDIR),)
  INCLUDE += -I $(LIBEVENTDIR)/include
  LDLIBS += -L $(LIBEVENTDIR)/.libs  -Wl,-rpath,$(LIBEVENTDIR)/.libs
endif

# Json library location explicitly specified - link against that.
ifneq ($(JSONCLIBDIR),)
	INCLUDE += -I $(JSONCLIBDIR)/include
	LDLIBS += -L $(JSONCLIBDIR)/lib -Wl,-rpath,$(JSONCLIBDIR)/lib -ljson-c
else
	JSON_C_CFLAGS := $(shell pkg-config --cflags json-c)
	CXXFLAG += $(JSON_C_CFLAGS)
	JSON_C_LIBS := $(shell pkg-config --libs json-c)
	LDLIBS += $(JSON_C_LIBS)
endif

# Need gmock
GMOCKDIR ?= /usr/src/gmock
INCLUDE += -I $(GMOCKDIR)/include -I $(GMOCKDIR)/gtest/include
GTESTLIB = gmock/gtest/libgtest.a
GMOCKLIB = gmock/libgmock.a

# Allow user-system overrides
INCLUDE += -I /usr/local/include
LDLIBS += -L /usr/local/lib

CXXFLAGS = $(INCLUDE) $(CXXFLAG) $(LOCAL_CXXFLAGS)

# These tests will be built and run automatically.
TESTS = \
	base/notification_test \
	log/cluster_state_controller_test \
	log/database_test \
	log/etcd_consistent_store_test \
	log/file_storage_test \
	log/frontend_signer_test \
	log/log_lookup_test \
	log/log_signer_test \
	log/logged_certificate_test \
	log/signer_verifier_test \
	log/strict_consistent_store_test \
	log/tree_signer_test \
	merkletree/merkle_tree_test \
	merkletree/serial_hasher_test \
	merkletree/tree_hasher_test \
	monitor/database_test \
	proto/serializer_test \
	util/etcd_test \
	util/fake_etcd_test \
	util/json_wrapper_test \
	util/libevent_wrapper_test \
	util/masterelection_test \
	util/sync_etcd_test \
	util/sync_task_test \
	util/task_test

# These tests will be built, but not run.
DISABLED_TESTS = \
	log/database_large_test \
	merkletree/merkle_tree_large_test

# These tests are built, but need specific flags, so you should add
# them to the end of the "test" target commands.
# TODO(pphaneuf): We should try to make those tests "just work", and
# move them to TESTS with the others.
EXTRA_TESTS = \
	log/cert_checker_test \
	log/cert_submission_handler_test \
	log/cert_test \
	log/ct_extensions_test \
	log/frontend_test

all: client/ct server/ct-server server/ct-dns-server tools/ct-clustertool \
     tools/dump_cert tools/dump_sth util/bench_etcd util/etcd_masterelection \
     util/etcd_watch

tests: all $(TESTS) $(DISABLED_TESTS) $(EXTRA_TESTS)

.DELETE_ON_ERROR:

.PHONY: clean all test tests alltests benchmark clean

gmock/Makefile: $(GMOCKDIR)
	mkdir -p gmock && cd gmock && cmake $(GMOCKDIR)

gmock/libgmock.a: gmock/Makefile
	$(MAKE) -C gmock CPPFLAGS="$(CPPFLAGS)" CXXFLAGS="$(CXXFLAGS)" \
	  LDFLAGS="$(LDFLAGS)"

gmock/gtest/libgtest.a: gmock/libgmock.a

%/.depend: %/*.cc */*.h
	$(CXX) $(CXXFLAGS) -MM -MG $(filter %.cc,$^) | sed 's,\(.*\)\.o,$(@D)/\1.o,' >$(@).tmp
	mv $(@).tmp $@

### proto preprocessing
proto/%.pb.h proto/%.pb.cc: ../proto/%.proto
	protoc -I .. $^ --cpp_out=.

ifneq ($(MAKECMDGOALS),clean)
    include client/.depend
    include fetcher/.depend
    include log/.depend
    include merkletree/.depend
    include monitor/.depend
    include proto/.depend
    include server/.depend
    include util/.depend
endif

base/notification_test: base/notification.cc base/notification_test.o \
                        util/testing.o $(GTESTLIB)

### util/ targets
util/libutil.a: util/util.o util/openssl_util.o util/testing.o \
                util/json_wrapper.o util/thread_pool.o util/libevent_wrapper.o \
                util/etcd.o util/status.o util/sync_etcd.o util/fake_etcd.o \
                util/periodic_closure.o util/masterelection.o util/task.o \
                util/sync_task.o util/uuid.o
	rm -f $@
	ar -rcs $@ $^

util/json_wrapper_test: util/json_wrapper_test.o util/libutil.a $(GTESTLIB)

util/libevent_wrapper_test: util/libevent_wrapper_test.o util/libutil.a $(GTESTLIB)

util/etcd_test: util/etcd_test.o util/libutil.a $(GMOCKLIB) $(GTESTLIB)

util/fake_etcd_test: util/fake_etcd_test.o base/notification.o util/libutil.a \
                     $(GMOCKLIB) $(GTESTLIB)

util/sync_etcd_test: util/sync_etcd_test.o util/libutil.a base/notification.o \
                     $(GMOCKLIB) $(GTESTLIB)

util/masterelection_test: util/masterelection_test.o base/notification.o \
                          util/libutil.a $(GTESTLIB)

util/sync_task_test: util/sync_task_test.o base/notification.o util/libutil.a \
                     $(GTESTLIB)

util/task_test: util/task_test.o base/notification.o util/libutil.a $(GTESTLIB)

### proto/ targets
proto/libproto.a: proto/ct.pb.o proto/serializer.o
	rm -f $@
	ar -rcs $@ $^

proto/serializer_test: proto/serializer_test.o proto/libproto.a \
                       util/libutil.a $(GTESTLIB)

### merkletree/ targets
merkletree/libmerkletree.a: merkletree/compact_merkle_tree.o \
                            merkletree/merkle_tree.o \
                            merkletree/merkle_tree_math.o \
                            merkletree/merkle_verifier.o \
                            merkletree/serial_hasher.o merkletree/tree_hasher.o
	rm -f $@
	ar -rcs $@ $^

merkletree/merkle_tree_large_test: merkletree/merkle_tree_large_test.o \
                                   merkletree/libmerkletree.a util/libutil.a \
                                   $(GTESTLIB)

merkletree/merkle_tree_test: merkletree/merkle_tree_test.o \
                             merkletree/libmerkletree.a util/libutil.a \
                             $(GTESTLIB)

merkletree/serial_hasher_test: merkletree/serial_hasher_test.o \
                               merkletree/serial_hasher.o util/libutil.a \
                               $(GTESTLIB)

merkletree/tree_hasher_test: merkletree/tree_hasher_test.o \
                             merkletree/serial_hasher.o \
                             merkletree/tree_hasher.o util/libutil.a \
                             $(GTESTLIB)

### log/ targets
log/libcert.a: log/cert.o log/cert_checker.o log/cert_submission_handler.o \
               log/ct_extensions.o merkletree/serial_hasher.o
	rm -f $@
	ar -rcs $@ $^

log/libcluster.a: log/etcd_consistent_store_cert.o \
                  log/cluster_state_controller_cert.o \
                  log/strict_consistent_store_cert.o
	rm -f $@
	ar -rcs $@ $^

log/libdatabase.a: log/file_storage.o log/filesystem_ops.o log/file_db_cert.o \
                   log/sqlite_db_cert.o log/database.o
	rm -f $@
	ar -rcs $@ $^

log/liblog.a: log/log_signer.o log/signer.o log/verifier.o log/frontend.o \
              log/frontend_signer.o log/log_verifier.o log/tree_signer_cert.o \
              log/log_lookup_cert.o
	rm -f $@
	ar -rcs $@ $^

log/cert_test: log/cert_test.o log/cert.o log/ct_extensions.o util/libutil.a \
               merkletree/serial_hasher.o log/frontend.o proto/ct.pb.o \
               log/frontend_signer.o log/cert_submission_handler.o \
               log/log_signer.o log/signer.o log/verifier.o proto/serializer.o \
               log/cert_checker.o $(GTESTLIB)

log/cert_checker_test: log/cert_checker_test.o log/cert.o log/cert_checker.o \
                       log/ct_extensions.o util/libutil.a \
                       merkletree/serial_hasher.o log/frontend.o proto/ct.pb.o \
                       log/frontend_signer.o log/cert_submission_handler.o \
                       log/log_signer.o log/signer.o log/verifier.o \
                       proto/serializer.o log/cert_checker.o $(GTESTLIB)

log/cert_submission_handler_test: log/cert_submission_handler_test.o \
                                  log/libcert.a util/libutil.a \
                                  log/frontend.o log/frontend_signer.o \
                                  proto/libproto.a log/log_signer.o \
                                  log/signer.o log/verifier.o $(GTESTLIB)

log/cluster_state_controller_test: base/notification.o \
                                   log/cluster_state_controller_test.o \
                                   merkletree/serial_hasher.o \
                                   log/libcert.a log/libcluster.a \
                                   proto/libproto.a util/libutil.a $(GMOCKLIB) \
                                   $(GTESTLIB)

log/ct_extensions_test: log/ct_extensions_test.o log/libcert.a util/libutil.a \
                        log/liblog.a proto/ct.pb.o \
                        log/cert_submission_handler.o proto/serializer.o \
                        log/cert_checker.o $(GTESTLIB)

log/database_large_test: log/database_large_test.o log/libdatabase.a \
                         log/log_signer.o log/signer.o log/verifier.o \
                         log/test_signer.o merkletree/libmerkletree.a \
                         proto/libproto.a util/libutil.a $(GTESTLIB)

log/database_test: log/database_test.o log/libdatabase.a \
                   log/log_signer.o log/signer.o log/verifier.o \
                   log/test_signer.o merkletree/libmerkletree.a \
                   proto/libproto.a util/libutil.a $(GTESTLIB)

log/file_storage_test: log/file_storage_test.o log/libdatabase.a \
                       proto/libproto.a util/libutil.a \
                       merkletree/libmerkletree.a $(GTESTLIB)

log/frontend_signer_test: log/frontend_signer_test.o \
                          log/frontend_signer.o \
                          log/log_signer.o log/signer.o log/verifier.o \
                          log/log_verifier.o log/test_signer.o log/libcert.a \
                          log/libcluster.a log/libdatabase.a \
                          merkletree/libmerkletree.a \
                          proto/libproto.a util/libutil.a base/notification.o \
                          $(GTESTLIB) $(GMOCKLIB)

log/frontend_test: log/frontend_test.o log/frontend.o \
                   log/frontend_signer.o \
                   log/log_signer.o log/signer.o log/verifier.o \
                   log/log_verifier.o log/test_signer.o \
                   log/libcert.a log/libcluster.a log/libdatabase.a \
                   merkletree/libmerkletree.a \
                   proto/libproto.a util/libutil.a base/notification.o \
                   $(GTESTLIB) $(GMOCKLIB)

log/log_lookup_test: log/log_lookup_test.o log/test_signer.o \
                     log/libcluster.a log/libdatabase.a \
                     log/liblog.a merkletree/libmerkletree.a proto/libproto.a \
                     util/libutil.a base/notification.o $(GTESTLIB) $(GMOCKLIB)

log/log_signer_test: log/log_signer_test.o log/log_signer.o log/signer.o \
                     log/verifier.o log/test_signer.o \
                     log/libcluster.a merkletree/libmerkletree.a \
                     proto/libproto.a util/libutil.a $(GTESTLIB)

log/signer_verifier_test: log/signer_verifier_test.o log/log_signer.o \
                     log/signer.o log/verifier.o log/test_signer.o \
                     merkletree/libmerkletree.a proto/libproto.a \
                     util/libutil.a $(GTESTLIB)

log/tree_signer_test: log/tree_signer_test.o log/log_signer.o log/signer.o \
                      log/verifier.o log/test_signer.o log/tree_signer_cert.o \
                      log/log_verifier.o log/libcluster.a \
                      log/libdatabase.a merkletree/libmerkletree.a \
                      proto/libproto.a util/libutil.a base/notification.o \
                      $(GTESTLIB) $(GMOCKLIB)

log/logged_certificate_test: log/logged_certificate_test.o proto/libproto.a \
                             util/libutil.a merkletree/libmerkletree.a \
                             $(GTESTLIB)

log/etcd_consistent_store_test: base/notification.o \
                                log/etcd_consistent_store_cert.o \
                                proto/libproto.a util/libutil.a \
                                merkletree/libmerkletree.a $(GMOCKLIB) \
                                $(GTESTLIB)

log/strict_consistent_store_test: base/notification.o \
                                  log/strict_consistent_store_cert.o \
                                  proto/libproto.a util/libutil.a \
                                  $(GMOCKLIB) $(GTESTLIB)

monitor/database_test: monitor/database_test.o monitor/database.o \
                       monitor/sqlite_db.o util/libutil.a log/test_signer.o \
                       merkletree/libmerkletree.a log/log_signer.o \
                       log/signer.o log/verifier.o proto/libproto.a $(GTESTLIB)

# client
client/ct: client/ct.o client/client.o client/ssl_client.o \
           client/http_log_client.o log/logged_certificate.o \
           monitor/sqlite_db.o monitor/database.o monitor/monitor.o \
           client/async_log_client.o util/read_key.o $(LOCAL_LIBS)

server/ct-dns-server: server/ct-dns-server.o server/event.o $(LOCAL_LIBS)

server/ct-server: server/ct-server.o util/read_key.o server/handler.o \
	base/notification.o log/logged_certificate.o fetcher/fetcher.o \
        fetcher/peer.o fetcher/peer_group.o fetcher/remote_peer.o \
        client/async_log_client.o $(LOCAL_LIBS)

tools/ct-clustertool: tools/clustertool_main.o \
                      merkletree/libmerkletree.a util/read_key.o \
                      base/notification.o merkletree/serial_hasher.o \
                      log/libcluster.a log/libdatabase.a \
                      log/liblog.a util/libutil.a proto/libproto.a
	$(CXX) -o $@ $(LDLIBS) $^

tools/dump_cert: tools/dump_cert.o proto/libproto.a util/libutil.a

tools/dump_sth: tools/dump_sth.o proto/libproto.a

util/bench_etcd: util/bench_etcd.o util/libutil.a

util/etcd_masterelection: util/etcd_masterelection.o base/notification.o \
                          util/libutil.a

util/etcd_watch: util/etcd_watch.o util/etcd.o util/libevent_wrapper.o \
	util/json_wrapper.o util/status.o util/task.o util/sync_task.o \
	base/notification.o

test: tests
	@set -e; for TEST in $(TESTS); do \
		echo $$TEST; eval $$TEST; \
	done
	log/cert_test --test_certs_dir=../test/testdata
	log/cert_checker_test --test_certs_dir=../test/testdata
	log/cert_submission_handler_test --test_certs_dir=../test/testdata
	log/ct_extensions_test --test_certs_dir=../test/testdata
	log/frontend_test --test_certs_dir=../test/testdata
	# TODO(pphaneuf): This is broken by commit 9391d114, hopefully
	# fixed soon.
	#rm -rf /tmp/ct-test.$$$$ && mkdir /tmp/ct-test.$$$$ \
	#&& python server/ct-dns-server-test.py /tmp/ct-test.$$$$ \
	#&& rm -rf /tmp/ct-test.$$$$

# Unit tests plus end-to-end tests. Make sure to set up links in test/  first.
alltests: test
	$(MAKE) -C test test

benchmark: merkletree/merkle_tree_large_test log/database_large_test
	merkletree/merkle_tree_large_test
	@echo "----- Running database large test with --database_size=100 -----"
	log/database_large_test --database_size=100
	@echo "If you want to test other sizes, run log/database_large_test \
	with --database_size=x --batch_size=y"

clean:
	find . -name '*.[o|a]' | xargs rm -f
	find . -name '*_test' | xargs rm -f
	rm -f proto/*.pb.h proto/*.pb.cc */.depend*
	rm -rf gmock/*
