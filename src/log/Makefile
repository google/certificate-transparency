CXXFLAGS = -Wall -Werror -O3 -g
INCLUDE = -I ../include -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src
LOCAL_LIBS = liblog.a ../merkletree/libmerkle_tree.a
LIBS = $(LOCAL_LIBS) $(GTESTDIR)/make/gtest.a \
       -lpthread $(PROTOBUFDIR)/src/.libs/libprotobuf.a -lgflags -lglog -lssl \
       -lcrypto -lsqlite3

# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE += -I $(OPENSSLDIR)/include
  LIBS += -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -Wl,-rpath,$(OPENSSLDIR) \
	  -Wl,-rpath,$(OPENSSLDIR)/lib
endif

INCLUDE += -I /usr/local/include
LIBS += -L /usr/local/lib
CXXFLAGS += $(INCLUDE)

all: .depend cert_test cert_checker_test cert_submission_handler_test \
     file_storage_test database_test frontend_signer_test tree_signer_test \
     log_lookup_test database_large_test

# Preprocessing step for compiling .proto files.
../include/ct.pb.h: ../proto/ct.proto
	cd ../proto && $(MAKE)

.depend: *.cc *.h ../include/ct.pb.h
	$(CXX) $(CXXFLAGS) -MM *.cc *.h > .depend

clean:
	rm -f *test *.o *.a

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

liblog.a: cert.o cert_checker.o cert_submission_handler.o log_signer.o \
          file_storage.o filesystem_op.o file_db.o sqlite_db.o frontend.o \
          frontend_signer.o log_verifier.o tree_signer.o log_lookup.o
	rm -f $@
	ar -rcs $@ $^

cert_test: cert_test.o ../util/util.o ../util/testing.o $(LOCAL_LIBS)
	$(CXX) -o cert_test cert_test.o liblog.a ../util/util.o \
        ../util/testing.o $(LIBS)

cert_checker_test: cert_checker_test.o ../util/util.o ../util/testing.o \
                   $(LOCAL_LIBS)
	$(CXX) -o cert_checker_test cert_checker_test.o ../util/util.o \
        ../util/testing.o $(LIBS)

cert_submission_handler_test: cert_submission_handler_test.o \
			      ../util/util.o ../proto/ct.pb.o \
                              ../proto/serializer.o ../util/testing.o \
                              $(LOCAL_LIBS)
	$(CXX) -o cert_submission_handler_test cert_submission_handler_test.o \
	       ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
               ../util/testing.o $(LIBS)

log_signer_test: log_signer_test.o ../util/util.o \
	         ../proto/ct.pb.o ../proto/serializer.o test_signer.o \
                 ../util/testing.o $(LOCAL_LIBS)
	$(CXX) -o log_signer_test log_signer_test.o \
	       ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
	       test_signer.o ../util/testing.o $(LIBS)

file_storage_test: file_storage_test.o ../util/util.o ../proto/ct.pb.o \
                   ../proto/serializer.o ../util/testing.o $(LOCAL_LIBS)
	$(CXX) -o file_storage_test file_storage_test.o ../util/util.o \
               ../proto/ct.pb.o ../proto/serializer.o ../util/testing.o $(LIBS)

database_test: database_test.o ../util/util.o ../proto/ct.pb.o \
	       ../proto/serializer.o test_signer.o ../util/testing.o \
               $(LOCAL_LIBS)
	$(CXX) -o database_test database_test.o ../util/util.o \
	       ../proto/ct.pb.o ../proto/serializer.o test_signer.o \
               ../util/testing.o $(LIBS)

database_large_test: database_large_test.o \
                     ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
                     test_signer.o ../util/testing.o $(LOCAL_LIBS)
	$(CXX) -o database_large_test database_large_test.o ../util/util.o \
               ../proto/ct.pb.o ../proto/serializer.o test_signer.o \
               ../util/testing.o $(LIBS)

frontend_signer_test: frontend_signer_test.o test_signer.o \
		      ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
                      ../util/testing.o $(LOCAL_LIBS)
	$(CXX) -o frontend_signer_test frontend_signer_test.o \
		test_signer.o ../util/util.o ../proto/ct.pb.o \
                ../proto/serializer.o ../util/testing.o $(LIBS)

frontend_test: frontend_test.o test_signer.o \
	       ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
               ../util/testing.o $(LOCAL_LIBS)
	$(CXX) -o frontend_test frontend_test.o test_signer.o \
	       ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
               ../util/testing.o $(LIBS)

tree_signer_test: tree_signer_test.o \
		  ../util/util.o ../proto/ct.pb.o ../proto/serializer.o \
                  test_signer.o ../util/testing.o $(LOCAL_LIBS)
	$(CXX) -o tree_signer_test tree_signer_test.o ../util/util.o \
               ../proto/ct.pb.o \
	       ../proto/serializer.o test_signer.o ../util/testing.o $(LIBS)

log_lookup_test: log_lookup_test.o ../util/util.o ../proto/ct.pb.o \
	         ../proto/serializer.o test_signer.o ../util/testing.o \
                 $(LOCAL_LIBS)
	$(CXX) -o log_lookup_test log_lookup_test.o ../util/util.o \
               ../proto/ct.pb.o ../proto/serializer.o \
               test_signer.o ../util/testing.o $(LIBS)
