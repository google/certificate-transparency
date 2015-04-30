
AM_CPPFLAGS = \
	-I$(GMOCK_DIR)/include \
	-I$(GTEST_DIR)/include \
	$(json_c_CFLAGS)

AM_CXXFLAGS = \
	-fno-exceptions

BUILT_SOURCES = \
	cpp/gmock-all.cc \
	cpp/gtest-all.cc \
	cpp/monitoring/prometheus/metrics.pb.cc \
	cpp/monitoring/prometheus/metrics.pb.h \
	proto/ct.pb.cc \
	proto/ct.pb.h

bin_PROGRAMS = \
	cpp/client/ct \
	cpp/server/ct-server \
	cpp/tools/ct-clustertool

noinst_PROGRAMS = \
	cpp/tools/dump_cert \
	cpp/tools/dump_sth \
	cpp/tools/etcd_watch \
	cpp/util/bench_etcd \
	cpp/util/etcd_masterelection

if HAVE_LDNS
noinst_PROGRAMS += \
	cpp/server/ct-dns-server
endif

noinst_LIBRARIES = \
	cpp/libcore.a \
	cpp/libtest.a

check_PROGRAMS = \
	$(TESTS)

# TODO(pphaneuf): ct-dns-server-test.py has been disabled, because of
# commit 9391d114.
TESTS = \
	cpp/base/notification_test \
	cpp/log/cert_checker_test \
	cpp/log/cert_submission_handler_test \
	cpp/log/cert_test \
	cpp/log/cluster_state_controller_test \
	cpp/log/ct_extensions_test \
	cpp/log/database_large_test \
	cpp/log/database_test \
	cpp/log/etcd_consistent_store_test \
	cpp/log/file_storage_test \
	cpp/log/frontend_signer_test \
	cpp/log/frontend_test \
	cpp/log/log_lookup_test \
	cpp/log/log_signer_test \
	cpp/log/logged_certificate_test \
	cpp/log/signer_verifier_test \
	cpp/log/strict_consistent_store_test \
	cpp/log/tree_signer_test \
	cpp/merkletree/merkle_tree_large_test \
	cpp/merkletree/merkle_tree_test \
	cpp/merkletree/serial_hasher_test \
	cpp/merkletree/tree_hasher_test \
	cpp/monitor/database_test \
	cpp/monitoring/prometheus/counter_test \
	cpp/monitoring/prometheus/gauge_test \
	cpp/monitoring/registry_test \
	cpp/proto/serializer_test \
	cpp/server/proxy_test \
	cpp/util/etcd_delete_test \
	cpp/util/etcd_test \
	cpp/util/fake_etcd_test \
	cpp/util/json_wrapper_test \
	cpp/util/libevent_wrapper_test \
	cpp/util/masterelection_test \
	cpp/util/sync_task_test \
	cpp/util/task_test

all-local:
	$(MAKE) -C python

clean-local:
	$(MAKE) -C python clean
if HAVE_ANT
	$(ANT) clean
endif

%.pb.h %.pb.cc: %.proto
	$(AM_V_GEN)protoc $^ --cpp_out=.

cpp/gtest-all.cc: $(GTEST_DIR)/src/gtest-all.cc
	$(AM_V_at)cp $^ $@

cpp/gmock-all.cc: $(GMOCK_DIR)/src/gmock-all.cc
	$(AM_V_at)cp $^ $@

cpp_libcore_a_SOURCES = \
	cpp/base/notification.cc \
	cpp/fetcher/continuous_fetcher.cc \
	cpp/fetcher/fetcher.cc \
	cpp/fetcher/peer.cc \
	cpp/fetcher/peer_group.cc \
	cpp/log/cert.cc \
	cpp/log/cert_checker.cc \
	cpp/log/cert_submission_handler.cc \
	cpp/log/cluster_state_controller_cert.cc \
	cpp/log/ct_extensions.cc \
	cpp/log/database.cc \
	cpp/log/etcd_consistent_store_cert.cc \
	cpp/log/file_db_cert.cc \
	cpp/log/file_storage.cc \
	cpp/log/filesystem_ops.cc \
	cpp/log/frontend.cc \
	cpp/log/frontend_signer.cc \
	cpp/log/log_lookup_cert.cc \
	cpp/log/log_signer.cc \
	cpp/log/log_verifier.cc \
	cpp/log/logged_certificate.cc \
	cpp/log/signer.cc \
	cpp/log/sqlite_db_cert.cc \
	cpp/log/strict_consistent_store_cert.cc \
	cpp/log/tree_signer_cert.cc \
	cpp/log/verifier.cc \
	cpp/merkletree/compact_merkle_tree.cc \
	cpp/merkletree/merkle_tree.cc \
	cpp/merkletree/merkle_tree_math.cc \
	cpp/merkletree/merkle_verifier.cc \
	cpp/merkletree/serial_hasher.cc \
	cpp/merkletree/tree_hasher.cc \
	cpp/monitoring/prometheus/metrics.pb.cc \
	cpp/monitoring/prometheus/metrics.pb.h \
	cpp/monitoring/registry.cc \
	cpp/net/connection_pool.cc \
	cpp/net/url.cc \
	cpp/net/url_fetcher.cc \
	cpp/util/etcd.cc \
	cpp/util/etcd_delete.cc \
	cpp/util/fake_etcd.cc \
	cpp/util/masterelection.cc \
	cpp/util/status.cc \
	cpp/util/sync_task.cc \
	cpp/util/task.cc \
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

cpp_server_ct_server_LDADD = \
	cpp/libcore.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lcrypto -lprotobuf -lpthread -lsqlite3
cpp_server_ct_server_SOURCES = \
	cpp/client/async_log_client.cc \
	cpp/proto/serializer.cc \
	cpp/server/ct-server.cc \
	cpp/server/handler.cc \
	cpp/server/json_output.cc \
	cpp/server/metrics.cc \
	cpp/server/proxy.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/openssl_util.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/protobuf_util.h \
	cpp/util/read_key.cc \
	cpp/util/thread_pool.cc \
	cpp/util/util.cc \
	cpp/util/uuid.cc

cpp_tools_ct_clustertool_LDADD = \
	cpp/libcore.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lgflags -lglog -lpthread -lprotobuf -lcrypto -lsqlite3
cpp_tools_ct_clustertool_SOURCES = \
	cpp/proto/serializer.cc \
	cpp/tools/clustertool_main.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/read_key.cc \
	cpp/util/thread_pool.cc \
	cpp/util/util.cc

cpp_client_ct_LDADD = \
	cpp/libcore.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lcrypto -lssl -lpthread -lsqlite3
cpp_client_ct_SOURCES = \
	cpp/client/async_log_client.cc \
	cpp/client/client.cc \
	cpp/client/ct.cc \
	cpp/client/http_log_client.cc \
	cpp/client/ssl_client.cc \
	cpp/monitor/database.cc \
	cpp/monitor/monitor.cc \
	cpp/monitor/sqlite_db.cc \
	cpp/proto/serializer.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/openssl_util.cc \
	cpp/util/read_key.cc \
	cpp/util/util.cc

cpp_server_ct_dns_server_LDADD = \
	cpp/libcore.a \
	-lprotobuf -lgflags -lglog -lldns -lsqlite3 -lcrypto
cpp_server_ct_dns_server_SOURCES = \
	cpp/proto/serializer.cc \
	cpp/server/ct-dns-server.cc \
	cpp/server/event.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/util.cc

cpp_tools_dump_cert_LDADD = \
	cpp/libcore.a \
	-lprotobuf -lglog -lgflags
cpp_tools_dump_cert_SOURCES = \
	cpp/tools/dump_cert.cc \
	cpp/util/util.cc

cpp_tools_dump_sth_LDADD = \
	cpp/libcore.a \
	-lprotobuf -lglog -lgflags
cpp_tools_dump_sth_SOURCES = \
	cpp/tools/dump_sth.cc

cpp_tools_etcd_watch_LDADD = \
	cpp/libcore.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lgflags -lglog -lpthread
cpp_tools_etcd_watch_SOURCES = \
	cpp/tools/etcd_watch.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc

cpp_util_bench_etcd_LDADD = \
	cpp/libcore.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lgflags -lglog -lpthread
cpp_util_bench_etcd_SOURCES = \
	cpp/util/bench_etcd.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc

cpp_util_etcd_masterelection_LDADD = \
	cpp/libcore.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lgflags -lglog -lpthread -lprotobuf
cpp_util_etcd_masterelection_SOURCES = \
	cpp/util/etcd_masterelection.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc

cpp_base_notification_test_LDADD = \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread
cpp_base_notification_test_SOURCES = \
	cpp/base/notification.cc \
	cpp/base/notification_test.cc

cpp_log_cluster_state_controller_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lsqlite3 -lcrypto
cpp_log_cluster_state_controller_test_SOURCES = \
	cpp/client/async_log_client.cc \
	cpp/log/cluster_state_controller_test.cc \
	cpp/proto/serializer.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/openssl_util.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/thread_pool.cc \
	cpp/util/util.cc

cpp_log_database_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lsqlite3 -lpthread -lcrypto
cpp_log_database_test_SOURCES = \
	cpp/log/database_test.cc \
	cpp/log/test_signer.cc \
	cpp/proto/serializer.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/util.cc

cpp_log_etcd_consistent_store_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto
cpp_log_etcd_consistent_store_test_SOURCES = \
	cpp/log/etcd_consistent_store_test.cc \
	cpp/proto/serializer.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/thread_pool.cc \
	cpp/util/util.cc

cpp_log_file_storage_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto -lsqlite3
cpp_log_file_storage_test_SOURCES = \
	cpp/log/file_storage.cc \
	cpp/log/file_storage_test.cc \
	cpp/proto/serializer.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/util.cc

cpp_log_frontend_signer_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto -lsqlite3
cpp_log_frontend_signer_test_SOURCES = \
	cpp/log/frontend_signer_test.cc \
	cpp/log/test_signer.cc \
	cpp/proto/serializer.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/thread_pool.cc \
	cpp/util/util.cc

cpp_log_log_lookup_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto -lsqlite3
cpp_log_log_lookup_test_SOURCES = \
	cpp/log/log_lookup_test.cc \
	cpp/log/test_signer.cc \
	cpp/proto/serializer.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/thread_pool.cc \
	cpp/util/util.cc

cpp_log_log_signer_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto
cpp_log_log_signer_test_SOURCES = \
	cpp/log/log_signer_test.cc \
	cpp/log/test_signer.cc \
	cpp/proto/serializer.cc \
	cpp/util/util.cc

cpp_log_logged_certificate_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto
cpp_log_logged_certificate_test_SOURCES = \
	cpp/log/logged_certificate_test.cc \
	cpp/proto/serializer.cc \
	cpp/util/util.cc

cpp_log_strict_consistent_store_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread
cpp_log_strict_consistent_store_test_SOURCES = \
	cpp/log/strict_consistent_store_cert.cc \
	cpp/log/strict_consistent_store_test.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc

cpp_log_tree_signer_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto -lsqlite3
cpp_log_tree_signer_test_SOURCES = \
	cpp/log/test_signer.cc \
	cpp/log/tree_signer_test.cc \
	cpp/proto/serializer.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/thread_pool.cc \
	cpp/util/util.cc

cpp_log_signer_verifier_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto
cpp_log_signer_verifier_test_SOURCES = \
	cpp/log/signer_verifier_test.cc \
	cpp/log/test_signer.cc \
	cpp/proto/serializer.cc \
	cpp/util/util.cc

cpp_monitor_database_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lcrypto -lsqlite3 -lpthread
cpp_monitor_database_test_SOURCES = \
	cpp/log/test_signer.cc \
	cpp/monitor/database.cc \
	cpp/monitor/database_test.cc \
	cpp/monitor/sqlite_db.cc \
	cpp/proto/serializer.cc \
	cpp/util/util.cc

cpp_monitoring_prometheus_counter_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread
cpp_monitoring_prometheus_counter_test_SOURCES = \
	cpp/monitoring/prometheus/counter_test.cc \
	cpp/util/protobuf_util.cc

cpp_monitoring_prometheus_gauge_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread
cpp_monitoring_prometheus_gauge_test_SOURCES = \
	cpp/monitoring/prometheus/gauge_test.cc \
	cpp/util/protobuf_util.cc

cpp_monitoring_registry_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread
cpp_monitoring_registry_test_SOURCES = \
	cpp/monitoring/registry_test.cc \
	cpp/util/protobuf_util.cc

cpp_proto_serializer_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread
cpp_proto_serializer_test_SOURCES = \
	cpp/proto/serializer.cc \
	cpp/proto/serializer_test.cc \
	cpp/util/util.cc

cpp_server_proxy_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread
cpp_server_proxy_test_SOURCES = \
	cpp/server/json_output.cc \
	cpp/server/proxy.cc \
	cpp/server/proxy_test.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/protobuf_util.cc

cpp_util_etcd_delete_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread
cpp_util_etcd_delete_test_SOURCES = \
	cpp/util/etcd_delete_test.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/thread_pool.cc

cpp_util_etcd_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread
cpp_util_etcd_test_SOURCES = \
	cpp/util/etcd_test.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc

cpp_util_fake_etcd_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread
cpp_util_fake_etcd_test_SOURCES = \
	cpp/util/fake_etcd_test.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/thread_pool.cc

cpp_util_json_wrapper_test_LDADD = \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread
cpp_util_json_wrapper_test_SOURCES = \
	cpp/util/json_wrapper.cc \
	cpp/util/json_wrapper_test.cc \
	cpp/util/util.cc

cpp_util_libevent_wrapper_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread
cpp_util_libevent_wrapper_test_SOURCES = \
	cpp/util/libevent_wrapper.cc \
	cpp/util/libevent_wrapper_test.cc

cpp_util_masterelection_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread
cpp_util_masterelection_test_SOURCES = \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/masterelection_test.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc

cpp_merkletree_merkle_tree_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread -lcrypto
cpp_merkletree_merkle_tree_test_SOURCES = \
	cpp/util/util.cc \
	cpp/merkletree/merkle_tree_test.cc

cpp_merkletree_serial_hasher_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread -lcrypto
cpp_merkletree_serial_hasher_test_SOURCES = \
	cpp/util/util.cc \
	cpp/merkletree/serial_hasher_test.cc

cpp_merkletree_tree_hasher_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread -lcrypto
cpp_merkletree_tree_hasher_test_SOURCES = \
	cpp/util/util.cc \
	cpp/merkletree/tree_hasher_test.cc

cpp_util_sync_task_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread
cpp_util_sync_task_test_SOURCES = \
	cpp/util/sync_task_test.cc \
	cpp/util/thread_pool.cc

cpp_util_task_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread
cpp_util_task_test_SOURCES = \
	cpp/util/task_test.cc \
	cpp/util/thread_pool.cc

cpp_log_cert_checker_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread -lcrypto
cpp_log_cert_checker_test_SOURCES = \
	cpp/log/cert_checker_test.cc \
	cpp/util/openssl_util.cc \
	cpp/util/util.cc

cpp_log_cert_submission_handler_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto
cpp_log_cert_submission_handler_test_SOURCES = \
	cpp/log/cert_submission_handler_test.cc \
	cpp/util/openssl_util.cc \
	cpp/util/util.cc

cpp_log_cert_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread -lcrypto
cpp_log_cert_test_SOURCES = \
	cpp/log/cert_test.cc \
	cpp/util/openssl_util.cc \
	cpp/util/util.cc

cpp_log_ct_extensions_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread -lcrypto
cpp_log_ct_extensions_test_SOURCES = \
	cpp/log/ct_extensions_test.cc \
	cpp/util/openssl_util.cc \
	cpp/util/util.cc

cpp_log_database_large_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto -lsqlite3
cpp_log_database_large_test_SOURCES = \
	cpp/log/database_large_test.cc \
	cpp/log/test_signer.cc \
	cpp/proto/serializer.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/util.cc

cpp_log_frontend_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(json_c_LIBS) \
	$(libevent_LIBS) \
	-lglog -lgflags -lprotobuf -lpthread -lcrypto -lsqlite3
cpp_log_frontend_test_SOURCES = \
	cpp/log/frontend_test.cc \
	cpp/log/test_signer.cc \
	cpp/proto/serializer.cc \
	cpp/util/json_wrapper.cc \
	cpp/util/libevent_wrapper.cc \
	cpp/util/openssl_util.cc \
	cpp/util/periodic_closure.cc \
	cpp/util/protobuf_util.cc \
	cpp/util/thread_pool.cc \
	cpp/util/util.cc

cpp_merkletree_merkle_tree_large_test_LDADD = \
	cpp/libcore.a \
	cpp/libtest.a \
	$(libevent_LIBS) \
	-lglog -lgflags -lpthread -lcrypto
cpp_merkletree_merkle_tree_large_test_SOURCES = \
	cpp/merkletree/merkle_tree_large_test.cc \
	cpp/util/util.cc

docker: all
	sudo docker build -t localhost:5000/certificate_transparency/super_duper:test .
	cd cloud/etcd && sudo docker build -t localhost:5000/certificate_transparency/etcd:test .
	cd cloud/prometheus && sudo docker build -t localhost:5000/certificate_transparency/prometheus:test .
