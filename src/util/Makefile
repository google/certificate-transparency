CXXFLAG= -Wall -Werror -O3 -g
G_INCLUDE= -I $(PROTOBUFDIR)/src -I ../include
G_LIBS= $(PROTOBUFDIR)/.libs/libprotobuf.a

INCLUDE= $(G_INCLUDE)
LIBS= $(G_LIBS)

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
