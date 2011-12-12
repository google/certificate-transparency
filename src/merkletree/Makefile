CXXFLAGS= -Wall
LIBS= -lssl

all: test

test: SerialHasherTest TreeHasherTest

SerialHasherTest: SerialHasher.o SerialHasherTest.o
	$(CXX) -o SerialHasherTest SerialHasher.o SerialHasherTest.o $(LIBS)

TreeHasherTest: SerialHasher.o TreeHasher.o TreeHasherTest.o
	$(CXX) -o TreeHasherTest SerialHasher.o TreeHasher.o TreeHasherTest.o $(LIBS)

clean:
	rm *Test *.o
