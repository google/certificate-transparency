CXXFLAGS= -Wall
LIBS= -lcrypto

all: test

test: MerkleTreeTest SerialHasherTest TreeHasherTest

MerkleTreeTest: MerkleTree.o SerialHasher.o TreeHasher.o MerkleTreeTest.o
	$(CXX) -o  MerkleTreeTest MerkleTree.o SerialHasher.o TreeHasher.o MerkleTreeTest.o $(LIBS)

SerialHasherTest: SerialHasher.o SerialHasherTest.o
	$(CXX) -o SerialHasherTest SerialHasher.o SerialHasherTest.o $(LIBS)

TreeHasherTest: SerialHasher.o TreeHasher.o TreeHasherTest.o
	$(CXX) -o TreeHasherTest SerialHasher.o TreeHasher.o TreeHasherTest.o $(LIBS)

clean:
	rm *Test *.o
