#include <fstream>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <iostream>

#include "proto/ct.pb.h"
#include "util/util.h"
#include "version.h"

using std::cout;
using std::endl;
using std::ifstream;

namespace {


void DumpLoggedCert(const char* filename) {
  ifstream input(filename);
  ct::LoggedCertificatePB pb;
  CHECK(pb.ParseFromIstream(&input));

  if (pb.has_sequence_number())
    cout << "sequence number: " << pb.sequence_number() << endl;

  if (pb.has_merkle_leaf_hash())
    cout << "merkle_leaf_hash: " << util::ToBase64(pb.merkle_leaf_hash())
         << endl;

  if (pb.contents().has_sct())
    cout << "--- begin sct" << endl << pb.contents().sct().DebugString()
         << "--- end sct" << endl;

  if (pb.contents().has_entry())
    cout << "--- begin entry" << endl << pb.contents().entry().DebugString()
         << "--- end entry" << endl;
}


}  // namespace


int main(int argc, char* argv[]) {
  google::SetVersionString(cert_trans::kBuildVersion);
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  LOG(INFO) << "Build version: " << google::VersionString();

  for (int i = 1; i < argc; ++i)
    DumpLoggedCert(argv[i]);

  return 0;
}
