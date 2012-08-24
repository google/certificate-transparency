CXXFLAG= -Wall -Werror -O3 -g
G_INCLUDE= -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src
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

OBJS= ../merkletree/LogDB.o ../merkletree/SerialHasher.o \
../util/ct_debug.o ../util/util.o \
../log/cert_checker.o ../log/cert.o \
../log/submission_handler.o ../log/cert_submission_handler.o \
../log/log_signer.o ../log/frontend_signer.o \
../proto/ct.pb.o ../proto/serializer.o

all: .depend ct-server

# Preprocessing step for compiling .proto files.
../proto/ct.pb.h:
	cd ../proto && $(MAKE)

clean:
	rm -f *.o ct-server

include .depend

.depend: *.cc
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

ct-server: ct-server.cc $(OBJS)
	$(CXX) $(CXXFLAGS) -o ct-server ct-server.cc $(OBJS) $(LIBS)
