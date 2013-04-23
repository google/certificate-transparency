all: ct/proto/client_pb2.py

ct/proto/%_pb2.py: ct/proto/%.proto
	protoc $^ --python_out=.

test:
	./ct/client/mongo_db_test.py