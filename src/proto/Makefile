CXXFLAG= -Wall -Werror -O3 -g
INCLUDE= -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src -I ../include
LIBS= $(GTESTDIR)/make/gtest.a -lpthread $(PROTOBUFDIR)/src/.libs/libprotobuf.a

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

serializer_test: serializer_test.o serializer.o ct.pb.o ../util/util.o
	$(CXX) -o serializer_test serializer_test.o serializer.o ct.pb.o \
	../util/util.o $(LIBS)
