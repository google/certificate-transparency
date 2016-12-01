PROTOC?=protoc
INSTALL_DIR?=`pwd`/../../install

all: ct/proto/client_pb2.py ct/proto/ct_pb2.py ct/proto/tls_options_pb2.py \
	ct/proto/test_message_pb2.py ct/proto/certificate_pb2.py

ct/proto/%_pb2.py: ct/proto/%.proto
	$(PROTOC) $^ -I/usr/include/ -I/usr/local/include -I$(INSTALL_DIR)/include -I. --python_out=.

ct/proto/ct_pb2.py: ../proto/ct.proto
	$(PROTOC) --python_out=ct/proto -I../proto ../proto/ct.proto

test: all
	python -m unittest discover -p '*_test.py'

clean:
	cd ct/proto && rm -f *_pb2.py *.pb.cc *.pb.h
	find . -name '*.pyc' | xargs rm -f
