# A simple top-level Makefile acting as a shortcut for the various languages
# build and test commands.
all: cpp java python

.DELETE_ON_ERROR:
.PHONY: clean all alltests clean \
	java java_test java_clean cpp cpp_test cpp_clean \
	python python_test	

java:
	ant build

java_test: java
	ant test

java_clean:
	ant clean

cpp:
	cd cpp && make

cpp_test: cpp
	cd cpp && make test

cpp_clean:
	cd cpp && make clean

python:
	cd python && make

python_test: python
	cd python && make test

alltests: cpp_test java_test python_test

clean: cpp_clean java_clean
