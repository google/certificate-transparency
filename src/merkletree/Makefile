CXXFLAG= -Wall -Werror -O3 -g
G_INCLUDE= -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src -I ../include
G_LIBS= $(GTESTDIR)/make/gtest.a -lpthread $(PROTOBUFDIR)/src/.libs/libprotobuf.a
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE= $(G_INCLUDE) -I $(OPENSSLDIR)/include
  LIBS= $(G_LIBS) -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -lcrypto -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
else
  INCLUDE= $(G_INCLUDE)
  LIBS= $(G_LIBS) -lcrypto
endif

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: .depend MerkleTreeTest SerialHasherTest TreeHasherTest

clean:
	rm -f *Test *.o

include .depend

.depend: *.cc *.h
	$(CXX) $(CXXFLAGS) -MM *.cc *.h > .depend

test: MerkleTreeTest SerialHasherTest TreeHasherTest
	./SerialHasherTest
	./TreeHasherTest
# Do not run performance stress tests by default
	./MerkleTreeTest --gtest_filter=-*StressTest*

MerkleTreeTest: MerkleTree.o MerkleVerifier.o SerialHasher.o TreeHasher.o \
		MerkleTreeTest.o ../util/util.o
	$(CXX) -o  MerkleTreeTest MerkleVerifier.o MerkleTree.o SerialHasher.o \
	TreeHasher.o MerkleTreeTest.o ../util/util.o $(LIBS)

SerialHasherTest: SerialHasher.o SerialHasherTest.o ../util/util.o
	$(CXX) -o SerialHasherTest SerialHasher.o SerialHasherTest.o \
	../util/util.o $(LIBS)

TreeHasherTest: SerialHasher.o TreeHasher.o TreeHasherTest.o ../util/util.o
	$(CXX) -o TreeHasherTest SerialHasher.o TreeHasher.o TreeHasherTest.o \
	../util/util.o $(LIBS)
