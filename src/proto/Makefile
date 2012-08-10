CXXFLAG= -Wall -Werror -O3 -g
INCLUDE= -I $(GTESTDIR)/include -I $(PROTOBUFDIR)
LIBS= $(GTESTDIR)/libgtest.a -lpthread $(PROTOBUFDIR)/.libs/libprotobuf.a

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: ct.pb.h .depend serializer_test

ct.pb.h: ct.proto
	$(PROTOBUFDIR)/protoc ct.proto --cpp_out=.

.depend: *.cc
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

clean:
	rm -f *.o *pb.h *pb.cc

include .depend

test: serializer_test
	./serializer_test

serializer_test: serializer_test.o serializer.o ct.pb.o ../util/util.o
	$(CXX) -o serializer_test serializer_test.o serializer.o ct.pb.o \
	../util/util.o $(LIBS)


