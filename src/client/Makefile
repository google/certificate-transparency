CXXFLAG= -Wall -Werror -g
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
../merkletree/MerkleVerifier.o ../merkletree/SerialHasher.o \
../merkletree/TreeHasher.o ../merkletree/LogVerifier.o 

all: .depend ct

.depend: *.cc
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

ct: ct.cc $(OBJS)
	$(CXX) $(CXXFLAGS) -o ct ct.cc $(OBJS) $(LIBS)

clean:
	rm -f *.o ct
