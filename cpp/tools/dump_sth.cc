#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>

#include "proto/ct.pb.h"

using std::cout;
using std::endl;
using std::ifstream;

namespace {


void DumpSth(const char *filename) {
  ifstream input(filename);
  ct::SignedTreeHead pb;
  CHECK(pb.ParseFromIstream(&input));

  cout << pb.DebugString() << endl;
}


}  // namespace


int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  for (int i = 1; i < argc; ++i)
    DumpSth(argv[i]);

  return 0;
}
