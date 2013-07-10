CXXFLAG = -Wall -Werror -g -O3
# sometimes needed for certain libcurlpp-dev installs; technically their bug.
CXXFLAG += -DHAVE_CONFIG_H
INCLUDE = -I.
LOCAL_LIBS = log/libcert.a log/libdatabase.a log/liblog.a \
             merkletree/libmerkletree.a proto/libproto.a util/libutil.a
SYS_LIBS = -lpthread -lgflags -lglog -lssl -lcrypto \
       -lsqlite3 -lprotobuf -lcurlpp -ljson -lcurl

PLATFORM = $(shell uname -s)
ifneq ($(PLATFORM), FreeBSD)
  SYS_LIBS += -lresolv
endif

# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE += -I $(OPENSSLDIR)/include
  SYS_LIBS += -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -Wl,-rpath,$(OPENSSLDIR) \
          -Wl,-rpath,$(OPENSSLDIR)/lib
endif

GTESTDIR ?= /usr/src/gtest
INCLUDE += -I $(GTESTDIR)/include

INCLUDE += -I /usr/local/include
SYS_LIBS += -L /usr/local/lib

CXXFLAGS = $(INCLUDE) $(CXXFLAG)

# File lists to simplify the rest of the Makefile

PROTO_TESTS = proto/serializer_test
MERKLETREE_TESTS = merkletree/merkle_tree_test \
                   merkletree/merkle_tree_large_test \
                   merkletree/serial_hasher_test merkletree/tree_hasher_test
LOG_TESTS = log/cert_test log/cert_checker_test \
            log/cert_submission_handler_test log/database_test \
            log/database_large_test log/file_storage_test \
            log/frontend_signer_test log/frontend_test log/log_lookup_test \
            log/log_signer_test log/tree_signer_test \
            log/logged_certificate_test log/ct_extensions_test
CLIENT_TESTS = client/json_wrapper_test
ALL_TESTS = $(PROTO_TESTS) $(MERKLETREE_TESTS) $(LOG_TESTS) \
             $(CLIENT_TESTS)

all: $(LOCAL_LIBS) unit_tests client/ct server/ct-server server/blob-server

.DELETE_ON_ERROR:
.PHONY: clean all unit_tests test alltests benchmark clean \
        proto_tests merkletree_tests log_tests client_tests

gtest/Makefile: $(GTESTDIR) Makefile
	mkdir -p gtest && cd gtest && cmake $(GTESTDIR)

gtest/libgtest.a: gtest/Makefile
	$(MAKE) -C gtest CPPFLAGS="$(CPPFLAGS)" CXXFLAGS="$(CXXFLAGS)" \
	  LDFLAGS="$(LDFLAGS)" gtest

$(ALL_TESTS): gtest/libgtest.a

proto/.depend: proto/*.cc */*.h
	$(CXX) $(CXXFLAGS) -MM -MG proto/*.cc > proto/.depend1
	sed 's,\(.*\)\.o,proto/\1.o,' > proto/.depend < proto/.depend1
	rm proto/.depend1

merkletree/.depend: merkletree/*.cc */*.h
	$(CXX) $(CXXFLAGS) -MM -MG merkletree/*.cc > merkletree/.depend1
	sed 's,\(.*\)\.o,merkletree/\1.o,' > merkletree/.depend \
					   < merkletree/.depend1
	rm merkletree/.depend1

log/.depend: log/*.cc */*.h
	$(CXX) $(CXXFLAGS) -MM -MG log/*.cc > log/.depend1
	sed 's,\(.*\)\.o,log/\1.o,' > log/.depend < log/.depend1
	rm log/.depend1

util/.depend: util/*.cc */*.h
	$(CXX) $(CXXFLAGS) -MM -MG util/*.cc > util/.depend1
	sed 's,\(.*\)\.o,util/\1.o,' > util/.depend < util/.depend1
	rm util/.depend1

client/.depend: client/*.cc */*.h
	$(CXX) $(CXXFLAGS) -MM -MG client/*.cc > client/.depend1
	sed 's,\(.*\)\.o,client/\1.o,' > client/.depend < client/.depend1
	rm client/.depend1

server/.depend: server/*.cc */*.h
	$(CXX) $(CXXFLAGS) -MM -MG server/*.cc > server/.depend1
	sed 's,\(.*\)\.o,server/\1.o,' > server/.depend < server/.depend1
	rm server/.depend1

### proto preprocessing
proto/%.pb.h proto/%.pb.cc: proto/%.proto
	protoc $^ --cpp_out=.

ifneq ($(MAKECMDGOALS),clean)
    include proto/.depend
    include merkletree/.depend
    include log/.depend
    include util/.depend
    include client/.depend
    include server/.depend
endif

unit_tests: proto_tests merkletree_tests log_tests client_tests

### util/ targets
util/libutil.a: util/util.o util/openssl_util.o util/testing.o
	rm -f $@
	ar -rcs $@ $^

### proto/ targets
proto/libproto.a: proto/ct.pb.o proto/serializer.o
	rm -f $@
	ar -rcs $@ $^

proto_tests: $(PROTO_TESTS)

proto/serializer_test: proto/serializer_test.o proto/libproto.a util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

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
                                   merkletree/libmerkletree.a util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

merkletree/merkle_tree_test: merkletree/merkle_tree_test.o \
                             merkletree/libmerkletree.a util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

merkletree/serial_hasher_test: merkletree/serial_hasher_test.o \
                               merkletree/serial_hasher.o util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

merkletree/tree_hasher_test: merkletree/tree_hasher_test.o \
                             merkletree/serial_hasher.o \
                             merkletree/tree_hasher.o util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

### log/ targets
log/libcert.a: log/cert.o log/cert_checker.o log/cert_submission_handler.o \
               log/ct_extensions.o merkletree/serial_hasher.o
	rm -f $@
	ar -rcs $@ $^

log/libdatabase.a: log/file_storage.o log/filesystem_op.o log/file_db_cert.o \
                   log/sqlite_db_cert.o
	rm -f $@
	ar -rcs $@ $^

log/liblog.a: log/log_signer.o log/frontend.o log/frontend_signer.o \
              log/log_verifier.o log/tree_signer_cert.o log/log_lookup_cert.o
	rm -f $@
	ar -rcs $@ $^

log_tests: $(LOG_TESTS)

log/cert_test: log/cert_test.o log/cert.o log/ct_extensions.o util/libutil.a \
               merkletree/serial_hasher.o
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/cert_checker_test: log/cert_checker_test.o log/cert.o log/cert_checker.o \
                       log/ct_extensions.o util/libutil.a \
                       merkletree/serial_hasher.o
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/cert_submission_handler_test: log/cert_submission_handler_test.o \
                                  log/libcert.a proto/libproto.a \
                                  util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/ct_extensions_test: log/ct_extensions_test.o log/libcert.a util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/database_large_test: log/database_large_test.o log/libdatabase.a \
                         log/log_signer.o log/test_signer.o \
                         merkletree/libmerkletree.a proto/libproto.a \
                         util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/database_test: log/database_test.o log/libdatabase.a \
                   log/log_signer.o log/test_signer.o \
                   merkletree/libmerkletree.a proto/libproto.a util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/file_storage_test: log/file_storage_test.o log/libdatabase.a \
                       proto/libproto.a util/libutil.a \
                       merkletree/libmerkletree.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/frontend_signer_test: log/frontend_signer_test.o \
                          log/frontend_signer.o \
                          log/log_signer.o log/log_verifier.o \
                          log/test_signer.o log/libcert.a \
                          log/libdatabase.a merkletree/libmerkletree.a \
                          proto/libproto.a util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/frontend_test: log/frontend_test.o log/frontend.o \
                   log/frontend_signer.o \
                   log/log_signer.o log/log_verifier.o log/test_signer.o \
                   log/libcert.a log/libdatabase.a merkletree/libmerkletree.a \
                   proto/libproto.a util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/log_lookup_test: log/log_lookup_test.o log/test_signer.o log/libdatabase.a \
                     log/liblog.a merkletree/libmerkletree.a proto/libproto.a \
                     util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/log_signer_test: log/log_signer_test.o log/log_signer.o log/test_signer.o \
                     merkletree/libmerkletree.a proto/libproto.a util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/tree_signer_test: log/tree_signer_test.o log/log_signer.o \
                      log/test_signer.o log/tree_signer_cert.o \
                      log/log_verifier.o \
                      log/libdatabase.a merkletree/libmerkletree.a \
                      proto/libproto.a util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

log/logged_certificate_test: log/logged_certificate_test.o proto/libproto.a \
                             util/libutil.a merkletree/libmerkletree.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

# client
client_tests: $(CLIENT_TESTS)

client/json_wrapper_test: client/json_wrapper_test.o util/libutil.a
	$(CXX) -o $@ $^ $(SYS_LIBS)

client/ct: client/ct.o client/client.o client/log_client.o client/ssl_client.o \
           client/http_log_client.o $(LOCAL_LIBS)
	$(CXX) -o $@ $^ $(SYS_LIBS)

# server
server/ct-server: server/ct-server.o server/event.o $(LOCAL_LIBS)
	$(CXX) -o $@ $^ $(SYS_LIBS)

server/blob-server: server/blob-server.o server/event.o \
                    server/sqlite_db_blob.o server/tree_signer_blob.o \
                    server/log_lookup_blob.o \
                    $(LOCAL_LIBS)
	$(CXX) -o $@ $^ $(SYS_LIBS)

test: all
	client/json_wrapper_test
	proto/serializer_test
	merkletree/serial_hasher_test
	merkletree/tree_hasher_test
	merkletree/merkle_tree_test
# Do not run merkletree/merkle_tree_large_test by default
	log/logged_certificate_test
	log/cert_test --test_certs_dir=test/testdata
	log/cert_checker_test --test_certs_dir=test/testdata
	log/cert_submission_handler_test --test_certs_dir=test/testdata
	log/ct_extensions_test --test_certs_dir=test/testdata
	log/file_storage_test
	log/database_test
# Do not run log/database_large_test by default
	log/log_signer_test
	log/frontend_signer_test
	log/frontend_test --test_certs_dir=test/testdata
	log/tree_signer_test
	log/log_lookup_test

# Unit tests plus end-to-end tests. Make sure to set up links in test/  first.
alltests: test
	cd test && $(MAKE) test

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
	rm -rf gtest/*
