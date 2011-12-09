CXXFLAGS= -Wall
LIBS= -lssl

all: test

test: SerialHasherTest

SerialHasherTest: SerialHasher.o SerialHasherTest.o
	$(CXX) -o SerialHasherTest SerialHasher.o SerialHasherTest.o $(LIBS)

SerialHasherTest.o: SerialHasherTest.cc

SerialHasher.o: SerialHasher.cc

clean:
	rm SerialHasherTest *.o