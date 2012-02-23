CXXFLAG= -Wall -Werror -O3
INCLUDE=
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE = -I $(OPENSSLDIR)/include
  LIBS= -L $(OPENSSLDIR)/lib -lcrypto -Wl,-rpath,$(OPENSSLDIR)/lib
else
  LIBS= -lcrypto
endif

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

OBJS= ../merkletree/LogDB.o ../merkletree/LogRecord.o \
../merkletree/MerkleTree.o ../merkletree/SerialHasher.o \
../merkletree/TreeHasher.o ../merkletree/TreeLogger.o 

all: .depend ct-server

.depend: *.cc
	$(CXX) -MM *.cc > .depend

ct-server: ct-server.cc $(OBJS)
	$(CXX) -o ct-server ct-server.cc $(OBJS) $(LIBS)

clean:
	rm -f *.o ct-server



