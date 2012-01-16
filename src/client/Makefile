CXXFLAGS= -Wall -Werror -g -O3
LIBS= -lcrypto

all: .depend ct

.depend: *.cc
	$(CXX) -MM *.cc > .depend

clean:
	rm -f *.o ct
