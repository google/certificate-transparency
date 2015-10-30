#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>

#include "proto/ct.pb.h"
#include "version.h"

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
  gflags::SetVersionString(cert_trans::kBuildVersion);
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  LOG(INFO) << "Build version: " << gflags::VersionString();

  for (int i = 1; i < argc; ++i)
    DumpSth(argv[i]);

  return 0;
}
