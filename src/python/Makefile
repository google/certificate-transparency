all: ct/proto/client_pb2.py ct/proto/ct_pb2.py

ct/proto/%_pb2.py: ct/proto/%.proto
	protoc $^ --python_out=.

ct/proto/ct_pb2.py: ../proto/ct.proto
	protoc --python_out=ct/proto --proto_path=../proto ../proto/ct.proto

test: all
	./ct/client/sqlite_db_test.py
	./ct/crypto/verify_test.py
