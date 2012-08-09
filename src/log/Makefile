CXXFLAG= -Wall -Werror -O3 -g
G_INCLUDE= -I $(GTESTDIR)/include -I $(PROTOBUFDIR)
G_LIBS= $(GTESTDIR)/libgtest.a -lpthread $(PROTOBUFDIR)/.libs/libprotobuf.a
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE= $(G_INCLUDE) -I $(OPENSSLDIR)/include
  LIBS= $(G_LIBS) -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -lssl -lcrypto -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
else
  INCLUDE= $(G_INCLUDE)
  LIBS= $(G_LIBS) -lssl -lcrypto
endif

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: proto .depend cert_test cert_checker_test submission_handler_test

proto::
	cd ../proto && $(MAKE)

.depend: *.cc
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

clean:
	rm -f *test *.o

include .depend

test: cert_test cert_checker_test submission_handler_test frontend_signer_test
	./cert_test
	./cert_checker_test
	./submission_handler_test
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

frontend_signer_test: frontend_signer_test.o frontend_signer.o \
	log_signer.o log_verifier.o submission_handler.o ../util/util.o \
	../proto/ct.pb.o ../proto/serializer.o \
	../merkletree/SerialHasher.o ../merkletree/TreeHasher.o \
	../merkletree/MerkleVerifier.o ../merkletree/LogDB.o
	$(CXX) -o frontend_signer_test frontend_signer_test.o \
	frontend_signer.o log_signer.o log_verifier.o \
	submission_handler.o ../util/util.o \
	../proto/ct.pb.o ../proto/serializer.o \
	../merkletree/SerialHasher.o ../merkletree/TreeHasher.o \
	../merkletree/MerkleVerifier.o ../merkletree/LogDB.o $(LIBS)