CXXFLAG= -Wall -Werror -O3 -g
G_INCLUDE= -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src -I ../include
G_LIBS= $(GTESTDIR)/make/gtest.a -lpthread $(PROTOBUFDIR)/src/.libs/libprotobuf.a
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE= $(G_INCLUDE) -I $(OPENSSLDIR)/include
  LIBS= $(G_LIBS) -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -lssl -lcrypto -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
else
  INCLUDE= $(G_INCLUDE)
  LIBS= $(G_LIBS) -lssl -lcrypto
endif

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: .depend cert_test cert_checker_test submission_handler_test \
	file_storage_test database_test frontend_signer_test

# Preprocessing step for compiling .proto files.
../include/ct.pb.h: ../proto/ct.proto
	cd ../proto && $(MAKE)

.depend: *.cc *.h ../include/ct.pb.h
	$(CXX) $(CXXFLAGS) -MM *.cc *.h > .depend

clean:
	rm -f *test *.o

include .depend

test: cert_test cert_checker_test submission_handler_test log_signer_test \
	file_storage_test database_test frontend_signer_test
	./cert_test
	./cert_checker_test
	./submission_handler_test
	./log_signer_test
	./file_storage_test
	./database_test
	./frontend_signer_test

cert_test: cert_test.o cert.o ../util/util.o
	$(CXX) -o cert_test cert_test.o cert.o ../util/util.o $(LIBS)

cert_checker_test: cert_checker_test.o cert_checker.o cert.o ../util/util.o
	$(CXX) -o cert_checker_test cert_checker_test.o cert_checker.o \
	cert.o ../util/util.o $(LIBS)

submission_handler_test: submission_handler_test.o submission_handler.o \
	cert_checker.o cert.o cert_submission_handler.o \
	../util/util.o ../proto/ct.pb.o ../proto/serializer.o
	$(CXX) -o submission_handler_test submission_handler_test.o \
	submission_handler.o cert_checker.o cert.o \
	../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
	cert_submission_handler.o $(LIBS)

log_signer_test: log_signer_test.o log_signer.o ../util/util.o \
	../proto/ct.pb.o ../proto/serializer.o
	$(CXX) -o log_signer_test log_signer_test.o log_signer.o \
	../util/util.o ../proto/ct.pb.o ../proto/serializer.o $(LIBS)

file_storage_test: file_storage_test.o file_storage.o filesystem_op.o \
		   ../util/util.o
	$(CXX) -o file_storage_test file_storage_test.o file_storage.o \
		filesystem_op.o ../util/util.o $(LIBS)

database_test: database_test.o file_db.o file_storage.o \
	 filesystem_op.o ../util/util.o ../proto/ct.pb.o
	$(CXX) -o database_test database_test.o file_db.o file_storage.o \
		filesystem_op.o ../util/util.o ../proto/ct.pb.o $(LIBS)

frontend_signer_test: frontend_signer_test.o frontend_signer.o \
		      log_signer.o log_verifier.o submission_handler.o \
		      ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
		      ../merkletree/SerialHasher.o ../merkletree/TreeHasher.o \
		      ../merkletree/MerkleVerifier.o file_db.o file_storage.o \
		      filesystem_op.o
	$(CXX) -o frontend_signer_test frontend_signer_test.o \
		frontend_signer.o log_signer.o log_verifier.o \
		submission_handler.o ../util/util.o \
		../proto/ct.pb.o ../proto/serializer.o \
		../merkletree/SerialHasher.o ../merkletree/TreeHasher.o \
		../merkletree/MerkleVerifier.o file_db.o file_storage.o \
		filesystem_op.o $(LIBS)
