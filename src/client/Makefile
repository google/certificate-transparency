CXXFLAG = -Wall -Werror -O3 -g
INCLUDE = -I ../include -I $(GTESTDIR)/include -I $(PROTOBUFDIR)/src
LIBS = $(GTESTDIR)/make/gtest.a -lpthread \
       $(PROTOBUFDIR)/src/.libs/libprotobuf.a -lgflags -lglog -lssl -lcrypto

# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE+= -I $(OPENSSLDIR)/include
  LIBS+= -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
endif

INCLUDE += -I /usr/local/include
LIBS += -L /usr/local/lib
CXXFLAGS += $(INCLUDE)

OBJS= client.o log_client.o ssl_client.o ../proto/ct.pb.o \
      ../proto/serializer.o ../util/util.o ../log/liblog.a \
      ../merkletree/libmerkle_tree.a

all: .depend ct

# Preprocessing step for compiling .proto files.
../include/ct.pb.h: ../proto/ct.proto
	cd ../proto && $(MAKE)

.depend: *.cc *.h ../include/ct.pb.h
	$(CXX) $(CXXFLAGS) -MM *.cc *.h > .depend

include .depend

ct: ct.cc $(OBJS)
	$(CXX) $(CXXFLAGS) -o ct ct.cc $(OBJS) $(LIBS)

clean:
	rm -f *.o ct
