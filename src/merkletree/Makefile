CXXFLAG= -Wall -Werror -O3 -g
GTEST_INCLUDE= -I $(GTESTDIR)/include
GTEST_LIBS= $(GTESTDIR)/libgtest.a -lpthread
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE= $(GTEST_INCLUDE) -I $(OPENSSLDIR)/include
  LIBS= $(GTEST_LIBS) -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -lcrypto -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
else
  INCLUDE= $(GTEST_INCLUDE)
  LIBS= $(GTEST_LIBS) -lcrypto
endif

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: .depend LogDBTest MerkleTreeTest SerialHasherTest TreeLoggerTest \
	TreeHasherTest faildb

include .depend

.depend: *.cc *.h
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

test: LogDBTest MerkleTreeTest SerialHasherTest TreeLoggerTest TreeHasherTest
	./SerialHasherTest
	./TreeHasherTest
	./MerkleTreeTest
	./LogDBTest
	./TreeLoggerTest

LogDBTest: LogDB.o LogDBTestConstants.o LogDBTest.o ../util/util.o
	$(CXX) -o LogDBTest LogDB.o LogDBTestConstants.o LogDBTest.o \
	../util/util.o $(LIBS)

MerkleTreeTest: MerkleTree.o MerkleVerifier.o SerialHasher.o TreeHasher.o \
		MerkleTreeTest.o ../util/util.o
	$(CXX) -o  MerkleTreeTest MerkleVerifier.o MerkleTree.o SerialHasher.o \
	TreeHasher.o MerkleTreeTest.o ../util/util.o $(LIBS)

SerialHasherTest: SerialHasher.o SerialHasherTest.o ../util/util.o
	$(CXX) -o SerialHasherTest SerialHasher.o SerialHasherTest.o \
	../util/util.o $(LIBS)

TreeLoggerTest: LogDB.o LogRecord.o LogVerifier.o MerkleTree.o \
		MerkleVerifier.o SerialHasher.o TreeHasher.o TreeLogger.o \
		TreeLoggerTest.o ../util/ct_debug.o ../util/util.o \
		../log/submission_handler.o ../log/log_entry.o ../log/cert.o \
		../log/log_signer.o
	$(CXX) -o TreeLoggerTest LogDB.o LogRecord.o LogVerifier.o \
	MerkleTree.o MerkleVerifier.o SerialHasher.o TreeHasher.o TreeLogger.o \
	TreeLoggerTest.o ../util/ct_debug.o ../util/util.o \
	../log/submission_handler.o ../log/log_entry.o ../log/cert.o \
	../log/log_signer.o $(LIBS)

TreeHasherTest: SerialHasher.o TreeHasher.o TreeHasherTest.o ../util/util.o
	$(CXX) -o TreeHasherTest SerialHasher.o TreeHasher.o TreeHasherTest.o \
	../util/util.o $(LIBS)

faildb: faildb.cc LogDB.o LogDBTestConstants.o ../util/util.o
	$(CXX) $(CXXFLAGS) -o faildb faildb.cc LogDB.o LogDBTestConstants.o \
	../util/util.o $(LIBS)

clean:
	rm *Test *.o
