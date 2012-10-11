CXXFLAG= -Wall -Werror -O3 -g
INCLUDE= -I ../include -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src
LIBS= $(GTESTDIR)/make/gtest.a -lpthread $(PROTOBUFDIR)/src/.libs/libprotobuf.a -lgflags -lglog -lssl -lcrypto
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE+= -I $(OPENSSLDIR)/include
  LIBS+= -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
endif

INCLUDE+= -I /usr/local/include
LIBS+= -L /usr/local/lib
CXXFLAGS= $(INCLUDE) $(CXXFLAG)

OBJS= client.o log_client.o ssl_client.o ../merkletree/merkle_verifier.o \
../merkletree/serial_hasher.o ../merkletree/tree_hasher.o \
../util/util.o ../log/cert.o ../log/log_signer.o ../log/log_verifier.o \
../log/cert_submission_handler.o ../log/cert_checker.o \
../proto/ct.pb.o ../proto/serializer.o

all: .depend ct

# Preprocessing step for compiling .proto files.
../include/ct.pb.h: ../proto/ct.proto
	cd ../proto && $(MAKE)

.depend: *.cc *.h ../include/ct.pb.h
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

include .depend

ct: ct.cc $(OBJS)
	$(CXX) $(CXXFLAGS) -o ct ct.cc $(OBJS) $(LIBS)

clean:
	rm -f *.o ct
