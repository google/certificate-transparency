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

OBJS= cache.o ../merkletree/MerkleVerifier.o \
../merkletree/SerialHasher.o ../merkletree/TreeHasher.o \
../util/ct_debug.o ../util/util.o ../log/cert.o \
../log/log_signer.o ../log/log_verifier.o ../log/submission_handler.o \
../log/cert_submission_handler.o ../log/cert_checker.o \
../proto/ct.pb.o ../proto/serializer.o

all: .depend ct

# Preprocessing step for compiling .proto files.
# TODO(ekasper): some versions of gcc don't flatten the path
../proto/ct.pb.h:
	cd ../proto && $(MAKE)

.depend: *.cc
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

include .depend

ct: ct.cc $(OBJS)
	$(CXX) $(CXXFLAGS) -o ct ct.cc $(OBJS) $(LIBS)

clean:
	rm -f *.o ct
