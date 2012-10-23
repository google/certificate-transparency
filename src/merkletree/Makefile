CXXFLAG = -Wall -Werror -O3 -g
INCLUDE = -I ../include -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src
LIBS = $(GTESTDIR)/make/gtest.a -lpthread \
       $(PROTOBUFDIR)/src/.libs/libprotobuf.a  -lgflags -lglog -lcrypto
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE += -I $(OPENSSLDIR)/include
  LIBS += -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -Wl,-rpath,$(OPENSSLDIR) \
	  -Wl,-rpath,$(OPENSSLDIR)/lib
endif

INCLUDE += -I /usr/local/include
LIBS += -L /usr/local/lib

CXXFLAGS += $(INCLUDE)

all: .depend merkle_tree_test serial_hasher_test tree_hasher_test

clean:
	rm -f *_test *.o *.a

include .depend

.depend: *.cc *.h
	$(CXX) $(CXXFLAGS) -MM *.cc *.h > .depend

test: merkle_tree_test serial_hasher_test tree_hasher_test
	./serial_hasher_test
	./tree_hasher_test
# Do not run performance stress tests by default
	./merkle_tree_test --gtest_filter=-*StressTest*

libmerkle_tree.a: merkle_tree.o merkle_verifier.o serial_hasher.o tree_hasher.o
	rm -f $@
	ar -rcs $@ $^

merkle_tree_test: merkle_tree_test.o ../util/util.o libmerkle_tree.a
	$(CXX) -o merkle_tree_test merkle_tree_test.o ../util/util.o \
		libmerkle_tree.a $(LIBS)

serial_hasher_test: serial_hasher_test.o ../util/util.o libmerkle_tree.a
	$(CXX) -o serial_hasher_test serial_hasher_test.o ../util/util.o \
		libmerkle_tree.a $(LIBS)

tree_hasher_test: tree_hasher_test.o ../util/util.o libmerkle_tree.a
	$(CXX) -o tree_hasher_test tree_hasher_test.o ../util/util.o \
		libmerkle_tree.a $(LIBS)
