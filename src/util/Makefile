CXXFLAGS= -Wall -Werror -g

all: .depend ct_debug.o util.o

.depend: *.cc
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

include .depend

clean:
	rm -f *.o