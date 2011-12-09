CC=g++

all: test

test: SerialHasherTest

SerialHasherTest: SerialHasher.o SerialHasherTest.cc
	$(CC) -lssl -o SerialHasherTest SerialHasher.o SerialHasherTest.cc

SerialHasher.o: SerialHasher.cc
	$(CC) -Wall -c SerialHasher.cc

clean:
	rm SerialHasherTest *.o