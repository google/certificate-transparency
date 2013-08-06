all: ct/proto/client_pb2.py ct/proto/ct_pb2.py

ct/proto/%_pb2.py: ct/proto/%.proto
	protoc $^ --python_out=.

ct/proto/ct_pb2.py: ../proto/ct.proto
	protoc --python_out=ct/proto --proto_path=../proto ../proto/ct.proto

test: all
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/sqlite_log_db_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/verify_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/merkle_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/pem_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/asn1/types_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/asn1/oid_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/asn1/x509_name_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/asn1/print_util_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/crypto/cert_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/sqlite_cert_db_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/sqlite_connection_test.py
	PYTHONPATH=$(PYTHONPATH):. ./ct/client/log_client_test.py
