CXXFLAG= -Wall -Werror -g
INCLUDE=
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE = -I $(OPENSSLDIR)/include
  LIBS= -L $(OPENSSLDIR)  -L $(OPENSSLDIR)/lib -lcrypto -lssl -Wl,-rpath,$(OPENSSLDIR)  -Wl,-rpath,$(OPENSSLDIR)/lib
else
  LIBS= -lcrypto -lssl
endif

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

OBJS= ../merkletree/LogDB.o ../merkletree/LogRecord.o \
../merkletree/MerkleTree.o ../merkletree/SerialHasher.o \
../merkletree/TreeHasher.o ../merkletree/TreeLogger.o \
../util/ct_debug.o ../util/util.o ../log/cert_checker.o ../log/cert.o \
../log/submission_handler.o ../log/cert_submission_handler.o \
../log/log_entry.o ../log/log_signer.o

all: .depend ct-server

include .depend

.depend: *.cc
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

ct-server: ct-server.cc $(OBJS)
	$(CXX) $(CXXFLAGS) -o ct-server ct-server.cc $(OBJS) $(LIBS)

clean:
	rm -f *.o ct-server
