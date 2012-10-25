CXXFLAG= -Wall -Werror -O3 -g
INCLUDE= -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src -I ../include
LIBS= $(GTESTDIR)/make/gtest.a -lpthread $(PROTOBUFDIR)/src/.libs/libprotobuf.a -lgflags -lglog -lcrypto
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE+= -I $(OPENSSLDIR)/include
  LIBS+= -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
endif

INCLUDE+= -I /usr/local/include
LIBS+= -L /usr/local/lib
CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: .depend serializer_test

ct.pb.cc ct.pb.h: ct.proto
	$(PROTOBUFDIR)/src/protoc ct.proto --cpp_out=.

.depend: *.cc *.h ct.pb.h ct.pb.cc
	$(CXX) $(CXXFLAGS) -MM *.cc *.h > .depend

clean:
	rm -f *.o *pb.h *pb.cc

include .depend

test: serializer_test
	./serializer_test

serializer_test: serializer_test.o serializer.o ct.pb.o ../util/util.o \
                 ../merkletree/serial_hasher.o ../util/testing.o
	$(CXX) -o serializer_test serializer_test.o serializer.o ct.pb.o \
	../util/util.o ../merkletree/serial_hasher.o ../util/testing.o $(LIBS)
