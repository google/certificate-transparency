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

all: .depend merkle_tree_test serial_hasher_test tree_hasher_test

clean:
	rm -f *Test *.o

include .depend

.depend: *.cc *.h
	$(CXX) $(CXXFLAGS) -MM *.cc *.h > .depend

test: merkle_tree_test serial_hasher_test tree_hasher_test
	./serial_hasher_test
	./tree_hasher_test
# Do not run performance stress tests by default
	./merkle_tree_test --gtest_filter=-*StressTest*

merkle_tree_test: merkle_tree.o merkle_verifier.o serial_hasher.o tree_hasher.o \
		merkle_tree_test.o ../util/util.o
	$(CXX) -o  merkle_tree_test merkle_verifier.o merkle_tree.o serial_hasher.o \
	tree_hasher.o merkle_tree_test.o ../util/util.o $(LIBS)

serial_hasher_test: serial_hasher.o serial_hasher_test.o ../util/util.o
	$(CXX) -o serial_hasher_test serial_hasher.o serial_hasher_test.o \
	../util/util.o $(LIBS)

tree_hasher_test: serial_hasher.o tree_hasher.o tree_hasher_test.o ../util/util.o
	$(CXX) -o tree_hasher_test serial_hasher.o tree_hasher.o tree_hasher_test.o \
	../util/util.o $(LIBS)
