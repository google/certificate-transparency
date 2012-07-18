CXXFLAG= -Wall -Werror -O3 -g
GTEST_INCLUDE= -I $(GTESTDIR)/include
GTEST_LIBS= $(GTESTDIR)/libgtest.a -lpthread
# Need OpenSSL >= 1.0.0
ifneq ($(OPENSSLDIR),)
  INCLUDE= $(GTEST_INCLUDE) -I $(OPENSSLDIR)/include
  LIBS= $(GTEST_LIBS) -L $(OPENSSLDIR) -L $(OPENSSLDIR)/lib -lssl -lcrypto -Wl,-rpath,$(OPENSSLDIR) -Wl,-rpath,$(OPENSSLDIR)/lib
else
  INCLUDE= $(GTEST_INCLUDE)
  LIBS= $(GTEST_LIBS) -lssl -lcrypto
endif

CXXFLAGS= $(INCLUDE) $(CXXFLAG)

all: .depend cert_test cert_checker_test submission_handler_test

.depend: *.cc
	$(CXX) $(CXXFLAGS) -MM *.cc > .depend

include .depend

test: cert_test cert_checker_test submission_handler_test
	./cert_test
	./cert_checker_test
	./submission_handler_test

cert_test: cert_test.o cert.o ../util/util.o
	$(CXX) -o cert_test cert_test.o cert.o ../util/util.o $(LIBS)

cert_checker_test: cert_checker_test.o cert_checker.o cert.o ../util/util.o
	$(CXX) -o cert_checker_test cert_checker_test.o cert_checker.o \
	cert.o ../util/util.o \
	$(LIBS)

submission_handler_test: submission_handler_test.o submission_handler.o \
	cert_checker.o cert.o cert_submission_handler.o ../util/util.o \
	log_entry.o
	$(CXX) -o submission_handler_test submission_handler_test.o \
	submission_handler.o cert_checker.o cert.o ../util/util.o \
	log_entry.o cert_submission_handler.o $(LIBS)

clean:
	rm -f *test *.o