CXXFLAGS= -Wall -Werror -g -O3
LIBS= -lcrypto

all: .depend ct

.depend: *.cc *.h
	$(CXX) -MM *.cc > .depend

clean:
	rm -f *.o ct
