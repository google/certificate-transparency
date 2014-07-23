all: ct/proto/client_pb2.py ct/proto/ct_pb2.py ct/proto/tls_options_pb2.py \
	ct/proto/test_message_pb2.py

ct/proto/%_pb2.py: ct/proto/%.proto
	protoc $^ -I/usr/include/ -I/usr/local/include -I. --python_out=.

ct/proto/ct_pb2.py: ../proto/ct.proto
	protoc --python_out=ct/proto -I../proto ../proto/ct.proto

test: all
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/sqlite_log_db_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/verify_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/merkle_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/pem_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/asn1/print_util_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/asn1/tag_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/asn1/types_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/asn1/oid_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/asn1/x509_time_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/cert_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/sqlite_cert_db_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/sqlite_connection_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/log_client_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/sqlite_temp_db_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/monitor_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/state_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/tls_message_test.py
# Tests using twisted trial instead of plain unittest.
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/async_log_client_test.py

clean:
	cd ct/proto && rm -f *_pb2.py *.pb.cc *.pb.h
	find . -name '*.pyc' | xargs -r rm
