ACLOCAL_AMFLAGS = -Im4

AM_CPPFLAGS = \
	-I$(GMOCK_DIR)/include \
	-I$(GTEST_DIR)/include \
	$(evhtp_CFLAGS) \
	$(icu_CFLAGS) \
	$(json_c_CFLAGS)

AM_CXXFLAGS = \
	-fno-exceptions

BUILT_SOURCES = \
	cpp/gmock-all.cc \
	cpp/gtest-all.cc \
	proto/ct.pb.cc \
	proto/ct.pb.h

CLEANFILES = \
	$(BUILT_SOURCES) \
	cpp/version.cc

AM_TESTS_ENVIRONMENT = \
	LD_LIBRARY_PATH=$(INSTALL_DIR)/lib

# TODO(pphaneuf): change these to autoconf substitutions
export PROTOC
export INSTALL_DIR

BUILD_VERSION = `git describe --abbrev=0 --dirty --always --tags`

.PHONY: FORCE
cpp/version.cc: FORCE
	$(AM_V_GEN)sed -e "s/%BUILD_VERSION%/$(BUILD_VERSION)/" cpp/version.cc.in >cpp/version.cc.tmp && diff cpp/version.cc.tmp cpp/version.cc >/dev/null 2>&1 || mv -f cpp/version.cc.tmp cpp/version.cc
	$(AM_V_at)$(RM) cpp/version.cc.tmp

bin_PROGRAMS = \
	cpp/client/ct

noinst_LIBRARIES = \
	cpp/libcore.a \
	cpp/libtest.a

check_PROGRAMS = \
	cpp/util/thread_pool_test \
	cpp/net/url_fetcher_test \
	$(TESTS)

TESTS = \
	cpp/base/notification_test \
	cpp/log/cert_checker_test \
	cpp/log/cert_submission_handler_test \
	cpp/log/cert_test \
	cpp/log/ct_extensions_test \
	cpp/log/log_signer_test \
	cpp/log/logged_entry_test \
	cpp/log/signer_verifier_test \
	cpp/merkletree/merkle_tree_large_test \
	cpp/merkletree/merkle_tree_test \
	cpp/merkletree/serial_hasher_test \
	cpp/merkletree/sparse_merkle_tree_test \
	cpp/merkletree/tree_hasher_test \
	cpp/merkletree/verifiable_map_test \
	cpp/monitoring/counter_test \
	cpp/monitoring/gauge_test \
	cpp/monitoring/registry_test \
	cpp/proto/serializer_test \
	cpp/proto/serializer_v2_test \
	cpp/util/json_wrapper_test \
	cpp/util/libevent_wrapper_test \
	cpp/util/sync_task_test \
	cpp/util/task_test

all-local:
	$(MAKE) -C python

clean-local:
	$(MAKE) -C python clean

%.pb.h %.pb.cc: %.proto
	$(AM_V_GEN)$(PROTOC) $^ --cpp_out=.

cpp/gtest-all.cc: $(GTEST_DIR)/src/gtest-all.cc
	$(AM_V_at)cp $^ $@

cpp/gmock-all.cc: $(GMOCK_DIR)/src/gmock-all.cc
	$(AM_V_at)cp $^ $@

test/testdata/urlfetcher_test_certs/localhost-key.pem: test/create_url_fetcher_test_certs.sh
	$(AM_V_GEN)test/create_url_fetcher_test_certs.sh

cpp_libcore_a_SOURCES = \
	cpp/base/notification.cc \
	cpp/log/cert.cc \
	cpp/log/cert_checker.cc \
	cpp/log/cert_submission_handler.cc \
	cpp/log/ct_extensions.cc \
	cpp/log/log_signer.cc \
	cpp/log/log_verifier.cc \
	cpp/log/logged_entry.cc \
	cpp/log/signer.cc \
	cpp/log/verifier.cc \
	cpp/merkletree/compact_merkle_tree.cc \
	cpp/merkletree/merkle_tree.cc \
	cpp/merkletree/merkle_tree_math.cc \
	cpp/merkletree/merkle_verifier.cc \
	cpp/merkletree/serial_hasher.cc \
	cpp/merkletree/sparse_merkle_tree.cc \
	cpp/merkletree/tree_hasher.cc \
	cpp/merkletree/verifiable_map.cc \
	cpp/monitoring/monitoring.cc \
	cpp/monitoring/registry.cc \
	cpp/net/connection_pool.cc \
	cpp/net/url.cc \
	cpp/net/url_fetcher.cc \
	cpp/proto/cert_serializer.cc \
	cpp/proto/serializer.cc \
	cpp/proto/serializer_v2.cc \
	cpp/proto/tls_encoding.cc \
	cpp/third_party/curl/hostcheck.c \
	cpp/third_party/isec_partners/openssl_hostname_validation.c \
	cpp/util/init.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/openssl_util.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/protobuf_util.h \
	cpp/util/read_key.cc \
	cpp/util/status.cc \
	cpp/util/sync_task.cc \
	cpp/util/task.cc \
	cpp/util/thread_pool.cc \
	cpp/util/thread_pool.h \
	cpp/util/util.cc \
	cpp/util/uuid.cc \
	cpp/version.cc \
	proto/ct.pb.cc \
	proto/ct.pb.h

cpp_libtest_a_CPPFLAGS = \
	-I$(GMOCK_DIR) \
	-I$(GTEST_DIR) \
	$(AM_CPPFLAGS)
cpp_libtest_a_SOURCES = \
	cpp/gmock-all.cc \
	cpp/gtest-all.cc \
	cpp/util/testing.cc

cpp_client_ct_LDADD = \
	cpp/libcore.a \
	$(evhtp_LIBS) \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_client_ct_SOURCES = \
	cpp/client/async_log_client.cc \
	cpp/client/client.cc \
	cpp/client/ct.cc \
	cpp/client/http_log_client.cc \
	cpp/client/ssl_client.cc \
	cpp/proto/cert_serializer.cc \
	cpp/proto/serializer.cc \
	cpp/util/init.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/read_key.cc \
	cpp/util/util.cc \
	cpp/version.cc

cpp_base_notification_test_LDADD = \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_base_notification_test_SOURCES = \
	cpp/base/notification.cc \
	cpp/base/notification_test.cc

cpp_log_log_signer_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_log_log_signer_test_SOURCES = \
	cpp/log/log_signer_test.cc \
	cpp/log/test_signer.cc \
	cpp/proto/serializer.cc \
	cpp/util/util.cc

cpp_log_logged_entry_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_log_logged_entry_test_SOURCES = \
	cpp/log/logged_entry_test.cc \
	cpp/proto/cert_serializer.cc \
	cpp/proto/serializer.cc \
	cpp/util/util.cc

cpp_log_signer_verifier_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_log_signer_verifier_test_SOURCES = \
	cpp/log/signer_verifier_test.cc \
	cpp/log/test_signer.cc \
	cpp/proto/cert_serializer.cc \
	cpp/proto/serializer.cc \
	cpp/util/util.cc

cpp_monitoring_counter_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_monitoring_counter_test_SOURCES = \
	cpp/monitoring/counter_test.cc \
	cpp/util/protobuf_util.cc

cpp_monitoring_gauge_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_monitoring_gauge_test_SOURCES = \
	cpp/monitoring/gauge_test.cc \
	cpp/util/protobuf_util.cc

cpp_monitoring_registry_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_monitoring_registry_test_SOURCES = \
	cpp/monitoring/registry_test.cc \
	cpp/util/protobuf_util.cc

cpp_net_url_fetcher_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_net_url_fetcher_test_SOURCES = \
	cpp/net/url_fetcher_test.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/protobuf_util.cc
EXTRA_cpp_net_url_fetcher_test_DEPENDENCIES = \
	test/testdata/urlfetcher_test_certs/localhost-key.pem

cpp_proto_serializer_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_proto_serializer_test_SOURCES = \
	cpp/proto/cert_serializer.cc \
	cpp/proto/serializer.cc \
	cpp/proto/serializer_test.cc \
	cpp/util/util.cc

cpp_proto_serializer_v2_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf -lcrypto
cpp_proto_serializer_v2_test_SOURCES = \
	cpp/proto/serializer_v2.cc \
	cpp/proto/serializer_v2_test.cc \
	cpp/util/util.cc

cpp_util_json_wrapper_test_LDADD = \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(json_c_LIBS) \
	$(libevent_LIBS)
cpp_util_json_wrapper_test_SOURCES = \
	cpp/util/json_wrapper.cc \
	cpp/util/json_wrapper_test.cc \
	cpp/util/util.cc

cpp_util_libevent_wrapper_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_util_libevent_wrapper_test_SOURCES = \
	cpp/util/libevent_wrapper.cc \
	cpp/util/libevent_wrapper_test.cc

cpp_merkletree_merkle_tree_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_merkletree_merkle_tree_test_SOURCES = \
	cpp/util/util.cc \
	cpp/merkletree/merkle_tree_test.cc

cpp_merkletree_serial_hasher_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_merkletree_serial_hasher_test_SOURCES = \
	cpp/util/util.cc \
	cpp/merkletree/serial_hasher_test.cc

cpp_merkletree_sparse_merkle_tree_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_merkletree_sparse_merkle_tree_test_SOURCES = \
	cpp/util/util.cc \
	cpp/merkletree/sparse_merkle_tree_test.cc

cpp_merkletree_tree_hasher_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_merkletree_tree_hasher_test_SOURCES = \
	cpp/util/util.cc \
	cpp/merkletree/tree_hasher_test.cc

cpp_merkletree_verifiable_map_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_merkletree_verifiable_map_test_SOURCES = \
	cpp/util/util.cc \
	cpp/merkletree/verifiable_map_test.cc

cpp_util_sync_task_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_util_sync_task_test_SOURCES = \
	cpp/util/sync_task_test.cc

cpp_util_task_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_util_task_test_SOURCES = \
	cpp/util/task_test.cc

cpp_util_thread_pool_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_util_thread_pool_test_SOURCES = \
	cpp/util/thread_pool_test.cc

cpp_log_cert_checker_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_log_cert_checker_test_SOURCES = \
	cpp/log/cert_checker_test.cc \
	cpp/util/util.cc

cpp_log_cert_submission_handler_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS) \
	-lprotobuf
cpp_log_cert_submission_handler_test_SOURCES = \
	cpp/log/cert_submission_handler_test.cc \
	cpp/util/util.cc

cpp_log_cert_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_log_cert_test_SOURCES = \
	cpp/log/cert_test.cc \
	cpp/util/util.cc

cpp_log_ct_extensions_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_log_ct_extensions_test_SOURCES = \
	cpp/log/ct_extensions_test.cc \
	cpp/util/util.cc

cpp_merkletree_merkle_tree_large_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(evhtp_LIBS) \
	$(libevent_LIBS)
cpp_merkletree_merkle_tree_large_test_SOURCES = \
	cpp/merkletree/merkle_tree_large_test.cc \
	cpp/util/util.cc

