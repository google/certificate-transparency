
# Make sure this is always first.
.PHONY: default
default: all

-include local.mk

CXXFLAG = -Wall -Werror -g -O3
LINK.o = $(LINK.cc)

INCLUDE = -I .
LOCAL_LIBS = log/libcert.a log/libdatabase.a log/liblog.a \
             merkletree/libmerkletree.a \
             proto/libproto.a util/libutil.a
LDLIBS = -lpthread -lgflags -lglog -lssl -lcrypto -lldns -lsqlite3 \
         -lprotobuf -levent_core -levent_extra -levent_pthreads

PLATFORM := $(shell uname -s)
ifeq ($(PLATFORM), FreeBSD)
  LDLIBS += -L/usr/local/lib/event2
else
  LDLIBS += -lresolv
endif

ifeq ($(PLATFORM), Darwin)
  LDLIBS += -lboost_system-mt -lboost_thread-mt
else
  LDLIBS += -lboost_system -lboost_thread
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

# File lists to simplify the rest of the Makefile

PROTO_TESTS = proto/serializer_test
MERKLETREE_TESTS = merkletree/merkle_tree_test \
                   merkletree/merkle_tree_large_test \
                   merkletree/serial_hasher_test merkletree/tree_hasher_test
LOG_TESTS = log/cert_test log/cert_checker_test \
            log/cert_submission_handler_test log/database_test \
            log/database_large_test log/file_storage_test \
            log/frontend_signer_test log/frontend_test log/log_lookup_test \
            log/signer_verifier_test log/log_signer_test log/tree_signer_test \
            log/logged_certificate_test log/ct_extensions_test
UTIL_TESTS = util/json_wrapper_test
MONITOR_TESTS = monitor/database_test
ALL_TESTS = $(PROTO_TESTS) $(MERKLETREE_TESTS) $(LOG_TESTS) $(UTIL_TESTS) \
	$(MONITOR_TESTS) dns_tests

all: unit_tests client/ct server/ct-server server/ct-dns-server \
     tools/dump_cert tools/dump_sth

.DELETE_ON_ERROR:

.PHONY: clean all unit_tests test alltests benchmark clean \
        proto_tests merkletree_tests log_tests client_tests \
	monitor_tests dns_tests

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
    include log/.depend
    include merkletree/.depend
    include monitor/.depend
    include proto/.depend
    include server/.depend
    include util/.depend
endif

unit_tests: proto_tests merkletree_tests log_tests util_tests monitor_tests

util_tests: util/json_wrapper_test

### util/ targets
util/libutil.a: util/util.o util/openssl_util.o util/testing.o \
                util/json_wrapper.o util/thread_pool.o util/libevent_wrapper.o
	rm -f $@
	ar -rcs $@ $^

util/json_wrapper_test: util/json_wrapper_test.o util/libutil.a $(GTESTLIB)

### proto/ targets
proto/libproto.a: proto/ct.pb.o proto/serializer.o
	rm -f $@
	ar -rcs $@ $^

proto_tests: $(PROTO_TESTS)

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

merkletree_tests: $(MERKLETREE_TESTS)

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

log/libdatabase.a: log/file_storage.o log/filesystem_op.o log/file_db_cert.o \
                   log/sqlite_db_cert.o
	rm -f $@
	ar -rcs $@ $^

log/liblog.a: log/log_signer.o log/signer.o log/verifier.o log/frontend.o \
              log/frontend_signer.o log/log_verifier.o log/tree_signer_cert.o \
              log/log_lookup_cert.o
	rm -f $@
	ar -rcs $@ $^

log_tests: $(LOG_TESTS)

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
                          log/libdatabase.a merkletree/libmerkletree.a \
                          proto/libproto.a util/libutil.a $(GTESTLIB)

log/frontend_test: log/frontend_test.o log/frontend.o \
                   log/frontend_signer.o \
                   log/log_signer.o log/signer.o log/verifier.o \
                   log/log_verifier.o log/test_signer.o \
                   log/libcert.a log/libdatabase.a merkletree/libmerkletree.a \
                   proto/libproto.a util/libutil.a $(GTESTLIB)

log/log_lookup_test: log/log_lookup_test.o log/test_signer.o log/libdatabase.a \
                     log/liblog.a merkletree/libmerkletree.a proto/libproto.a \
                     util/libutil.a $(GTESTLIB)

log/log_signer_test: log/log_signer_test.o log/log_signer.o log/signer.o \
                     log/verifier.o log/test_signer.o \
                     merkletree/libmerkletree.a proto/libproto.a \
                     util/libutil.a $(GTESTLIB)

log/signer_verifier_test: log/signer_verifier_test.o log/log_signer.o \
                     log/signer.o log/verifier.o log/test_signer.o \
                     merkletree/libmerkletree.a proto/libproto.a \
                     util/libutil.a $(GTESTLIB)

log/tree_signer_test: log/tree_signer_test.o log/log_signer.o log/signer.o \
                      log/verifier.o log/test_signer.o log/tree_signer_cert.o \
                      log/log_verifier.o \
                      log/libdatabase.a merkletree/libmerkletree.a \
                      proto/libproto.a util/libutil.a $(GTESTLIB)

log/logged_certificate_test: log/logged_certificate_test.o proto/libproto.a \
                             util/libutil.a merkletree/libmerkletree.a \
                             $(GTESTLIB)

monitor_tests: $(MONITOR_TESTS)

monitor/database_test: monitor/database_test.o monitor/database.o \
                       monitor/sqlite_db.o util/libutil.a log/test_signer.o \
                       merkletree/libmerkletree.a log/log_signer.o \
                       log/signer.o log/verifier.o proto/libproto.a $(GTESTLIB)

# client
client/ct: client/ct.o client/client.o client/ssl_client.o \
           client/http_log_client.o monitor/sqlite_db.o monitor/database.o \
           monitor/monitor.o client/async_log_client.o \
           $(LOCAL_LIBS)

server/ct-dns-server: server/ct-dns-server.o server/event.o $(LOCAL_LIBS)

server/ct-server: server/ct-server.o util/read_private_key.o \
	server/handler.o $(LOCAL_LIBS)

tools/dump_cert: tools/dump_cert.o proto/libproto.a util/libutil.a

tools/dump_sth: tools/dump_sth.o proto/libproto.a

dns_tests: server/ct-dns-server

test: all
	util/json_wrapper_test
	proto/serializer_test
	merkletree/serial_hasher_test
	merkletree/tree_hasher_test
	merkletree/merkle_tree_test
# Do not run merkletree/merkle_tree_large_test by default
	log/logged_certificate_test
	log/cert_test --test_certs_dir=../test/testdata
	log/cert_checker_test --test_certs_dir=../test/testdata
	log/cert_submission_handler_test --test_certs_dir=../test/testdata
	log/ct_extensions_test --test_certs_dir=../test/testdata
	log/file_storage_test
	log/database_test
# Do not run log/database_large_test by default
	log/log_signer_test
	log/frontend_signer_test
	log/frontend_test --test_certs_dir=../test/testdata
	log/tree_signer_test
	log/log_lookup_test
	monitor/database_test
	rm -rf /tmp/ct-test.$$$$ && mkdir /tmp/ct-test.$$$$ \
	&& python server/ct-dns-server-test.py /tmp/ct-test.$$$$ \
	&& rm -rf /tmp/ct-test.$$$$

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
