CXXFLAG= -Wall -Werror -O3 -g
INCLUDE= -I ../include -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src
LIBS= $(GTESTDIR)/make/gtest.a -lpthread $(PROTOBUFDIR)/src/.libs/libprotobuf.a -lgflags -lglog -lssl -lcrypto -lsqlite3
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE+= -I $(OPENSSLDIR)/include
  LIBS+= -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
endif

INCLUDE+= -I /usr/local/include
LIBS+= -L /usr/local/lib
CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: .depend cert_test cert_checker_test cert_submission_handler_test \
     file_storage_test database_test frontend_signer_test tree_signer_test \
     log_lookup_test database_large_test

# Preprocessing step for compiling .proto files.
../include/ct.pb.h: ../proto/ct.proto
	cd ../proto && $(MAKE)

.depend: *.cc *.h ../include/ct.pb.h
	$(CXX) $(CXXFLAGS) -MM *.cc *.h > .depend

clean:
	rm -f *test *.o

include .depend

ifneq ($(TMPDIR),)
  FLAGS= --database_test_dir=$(TMPDIR)
endif

test: cert_test cert_checker_test cert_submission_handler_test log_signer_test \
      file_storage_test database_test frontend_signer_test tree_signer_test \
      log_lookup_test database_large_test frontend_test
	./cert_test
	./cert_checker_test
	./cert_submission_handler_test
	./log_signer_test
	./file_storage_test $(FLAGS)
	./database_test $(FLAGS)
	./frontend_signer_test $(FLAGS)
	./tree_signer_test $(FLAGS)
	./log_lookup_test $(FLAGS)
	./frontend_test $(FLAGS)
# Do not run database large test by default

cert_test: cert_test.o cert.o ../util/util.o
	$(CXX) -o cert_test cert_test.o cert.o ../util/util.o $(LIBS)

cert_checker_test: cert_checker_test.o cert_checker.o cert.o ../util/util.o
	$(CXX) -o cert_checker_test cert_checker_test.o cert_checker.o cert.o \
	       ../util/util.o $(LIBS)

cert_submission_handler_test: cert_submission_handler_test.o \
			      cert_checker.o cert.o cert_submission_handler.o \
			      ../util/util.o ../proto/ct.pb.o \
                              ../proto/serializer.o \
                              ../merkletree/serial_hasher.o
	$(CXX) -o cert_submission_handler_test cert_submission_handler_test.o \
	       cert_checker.o cert.o ../util/util.o ../proto/ct.pb.o \
               ../proto/serializer.o cert_submission_handler.o \
               ../merkletree/serial_hasher.o $(LIBS)

log_signer_test: log_signer_test.o log_signer.o ../util/util.o \
	         ../proto/ct.pb.o ../proto/serializer.o test_signer.o \
                 ../merkletree/serial_hasher.o
	$(CXX) -o log_signer_test log_signer_test.o log_signer.o \
	       ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
	       test_signer.o ../merkletree/serial_hasher.o $(LIBS)

file_storage_test: file_storage_test.o file_storage.o filesystem_op.o \
		   ../util/util.o file_db.o sqlite_db.o ../proto/ct.pb.o \
                   ../proto/serializer.o ../merkletree/serial_hasher.o
	$(CXX) -o file_storage_test file_storage_test.o file_storage.o \
	       filesystem_op.o ../util/util.o file_db.o sqlite_db.o \
               ../proto/ct.pb.o ../proto/serializer.o \
               ../merkletree/serial_hasher.o $(LIBS)

database_test: database_test.o file_db.o file_storage.o \
	       filesystem_op.o sqlite_db.o ../util/util.o ../proto/ct.pb.o \
	       ../proto/serializer.o test_signer.o log_signer.o \
               ../merkletree/serial_hasher.o
	$(CXX) -o database_test database_test.o file_db.o file_storage.o \
		filesystem_op.o sqlite_db.o ../util/util.o ../proto/ct.pb.o \
		../proto/serializer.o test_signer.o log_signer.o \
                ../merkletree/serial_hasher.o $(LIBS)

database_large_test: database_large_test.o file_db.o file_storage.o \
	             filesystem_op.o sqlite_db.o \
                     ../util/util.o ../proto/ct.pb.o \
	             ../proto/serializer.o test_signer.o log_signer.o \
                     ../merkletree/serial_hasher.o
	$(CXX) -o database_large_test database_large_test.o file_db.o \
               file_storage.o filesystem_op.o sqlite_db.o ../util/util.o \
               ../proto/ct.pb.o ../proto/serializer.o test_signer.o \
               log_signer.o ../merkletree/serial_hasher.o $(LIBS)

frontend_signer_test: frontend_signer_test.o frontend_signer.o \
		      log_signer.o log_verifier.o test_signer.o \
		      ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
		      ../merkletree/serial_hasher.o \
                      ../merkletree/tree_hasher.o \
		      ../merkletree/merkle_verifier.o file_db.o file_storage.o \
		      filesystem_op.o sqlite_db.o
	$(CXX) -o frontend_signer_test frontend_signer_test.o \
		frontend_signer.o log_signer.o log_verifier.o test_signer.o \
		../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
		../merkletree/serial_hasher.o ../merkletree/tree_hasher.o \
		../merkletree/merkle_verifier.o file_db.o file_storage.o \
		filesystem_op.o sqlite_db.o $(LIBS)

frontend_test: frontend_test.o frontend_test.o frontend.o frontend_signer.o \
	       log_signer.o log_verifier.o test_signer.o \
               cert.o cert_checker.o cert_submission_handler.o \
	       ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
	       ../merkletree/serial_hasher.o ../merkletree/tree_hasher.o \
	       ../merkletree/merkle_verifier.o file_db.o file_storage.o \
	       filesystem_op.o sqlite_db.o
	$(CXX) -o frontend_test frontend_test.o frontend.o frontend_signer.o \
               log_signer.o log_verifier.o test_signer.o \
               cert.o cert_checker.o cert_submission_handler.o \
	       ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
	       ../merkletree/serial_hasher.o ../merkletree/tree_hasher.o \
	       ../merkletree/merkle_verifier.o file_db.o file_storage.o \
	       filesystem_op.o sqlite_db.o $(LIBS)

tree_signer_test: tree_signer_test.o tree_signer.o log_signer.o log_verifier.o \
		  ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
		  ../merkletree/serial_hasher.o ../merkletree/tree_hasher.o \
		  ../merkletree/merkle_tree.o ../merkletree/merkle_verifier.o \
		  file_db.o file_storage.o filesystem_op.o sqlite_db.o \
                  test_signer.o
	$(CXX) -o tree_signer_test tree_signer_test.o tree_signer.o \
		log_signer.o log_verifier.o ../util/util.o ../proto/ct.pb.o \
		../proto/serializer.o ../merkletree/serial_hasher.o \
		../merkletree/tree_hasher.o ../merkletree/merkle_tree.o \
		../merkletree/merkle_verifier.o file_db.o file_storage.o \
		filesystem_op.o sqlite_db.o test_signer.o $(LIBS)

log_lookup_test: log_lookup_test.o log_lookup.o tree_signer.o log_signer.o \
		 log_verifier.o ../util/util.o ../proto/ct.pb.o \
	         ../proto/serializer.o ../merkletree/serial_hasher.o \
		 ../merkletree/tree_hasher.o ../merkletree/merkle_tree.o \
		 ../merkletree/merkle_verifier.o file_db.o file_storage.o \
		 filesystem_op.o sqlite_db.o test_signer.o
	$(CXX) -o log_lookup_test log_lookup_test.o log_lookup.o tree_signer.o \
		log_signer.o log_verifier.o ../util/util.o ../proto/ct.pb.o \
		../proto/serializer.o ../merkletree/serial_hasher.o \
		../merkletree/tree_hasher.o ../merkletree/merkle_tree.o \
		../merkletree/merkle_verifier.o file_db.o file_storage.o \
		filesystem_op.o sqlite_db.o test_signer.o $(LIBS)
