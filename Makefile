CXX=g++
LDFLAGS=-lpthread -g -lshannondb_cxx
CXXFLAGS=-O2 -std=c++11

all: check

check: check.cc
	$(CXX) $(CXXFLAGS) $^ -o$@ $(LDFLAGS)

clean:
	rm -rf check
