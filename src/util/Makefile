CXXFLAG= -Wall -Werror -O3 -g
G_INCLUDE= -I $(PROTOBUFDIR)/src
G_LIBS= $(PROTOBUFDIR)/.libs/libprotobuf.a

INCLUDE= $(G_INCLUDE)
LIBS= $(G_LIBS)

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: .depend ct_debug.o util.o

.depend: *.cc
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

clean:
	rm -f *.o

include .depend
