CXXFLAG= -Wall -Werror -O3 -g
G_INCLUDE= -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src
G_LIBS= $(GTESTDIR)/make/gtest.a -lpthread $(PROTOBUFDIR)/src/.libs/libprotobuf.a
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE= $(G_INCLUDE) -I $(OPENSSLDIR)/include
  LIBS= $(G_LIBS) -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -lssl -lcrypto -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
else
  INCLUDE= $(G_INCLUDE)
  LIBS= $(G_LIBS) -lssl -lcrypto
endif

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: proto .depend LogDBTest MerkleTreeTest SerialHasherTest \
	TreeHasherTest faildb

proto::
	cd ../proto && $(MAKE)

clean:
	rm -f *Test *.o

include .depend

.depend: *.cc *.h
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

test: LogDBTest MerkleTreeTest SerialHasherTest TreeHasherTest
	./SerialHasherTest
	./TreeHasherTest
	./MerkleTreeTest
	./LogDBTest

LogDBTest: LogDB.o LogDBTestConstants.o LogDBTest.o ../util/util.o \
	../proto/ct.pb.o
	$(CXX) -o LogDBTest LogDB.o LogDBTestConstants.o LogDBTest.o \
	../util/util.o ../proto/ct.pb.o $(LIBS)

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

faildb: faildb.cc ../proto/ct.pb.o LogDB.o LogDBTestConstants.o ../util/util.o
	$(CXX) $(CXXFLAGS) -o faildb faildb.cc LogDB.o LogDBTestConstants.o \
	../proto/ct.pb.o ../util/util.o $(LIBS)

