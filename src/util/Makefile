CXXFLAG= -Wall -Werror -O3 -g
INCLUDE= -I ../include -I $(PROTOBUFDIR)/src 
LIBS= $(PROTOBUFDIR)/.libs/libprotobuf.a

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: .depend util.o

# Preprocessing step for compiling .proto files.
../include/ct.pb.h: ../proto/ct.proto
	cd ../proto && $(MAKE)

.depend: *.cc *.h ../include/ct.pb.h
	$(CXX) $(CXXFLAGS) -MM *.cc *.h > .depend

clean:
	rm -f *.o

include .depend
