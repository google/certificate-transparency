CXXFLAG= -Wall -Werror -O3 -g
G_INCLUDE= -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src -I ../include -I /usr/local/include
G_LIBS= $(GTESTDIR)/make/gtest.a -lpthread $(PROTOBUFDIR)/src/.libs/libprotobuf.a -L /usr/local/lib -lgflags -lglog
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE= $(G_INCLUDE) -I $(OPENSSLDIR)/include
  LIBS= $(G_LIBS) -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -lssl -lcrypto -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
else
  INCLUDE= $(G_INCLUDE)
  LIBS= $(G_LIBS) -lssl -lcrypto
endif

LIBS+= -L /usr/local/lib -lsqlite3

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

OBJS= ../merkletree/SerialHasher.o \
      ../util/ct_debug.o ../util/util.o \
      ../log/cert_checker.o ../log/cert.o \
      ../log/submission_handler.o ../log/cert_submission_handler.o \
      ../log/log_signer.o ../log/frontend_signer.o \
      ../log/file_db.o ../log/file_storage.o ../log/filesystem_op.o \
      ../log/sqlite_db.o ../proto/ct.pb.o ../proto/serializer.o

all: .depend ct-server

# Preprocessing step for compiling .proto files.
../include/ct.pb.h: ../proto/ct.proto
	cd ../proto && $(MAKE)

.depend: *.cc ../include/ct.pb.h
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

include .depend

ct-server: ct-server.cc $(OBJS)
	$(CXX) $(CXXFLAGS) -o ct-server ct-server.cc $(OBJS) $(LIBS)

clean:
	rm -f *.o ct-server
