#include <glog/logging.h>
#include <gtest/gtest.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/resource.h>
#include <string>
#include <vector>

#include "merkletree/merkle_tree.h"
#include "merkletree/serial_hasher.h"
#include "util/testing.h"
#include "util/util.h"

namespace {

using std::string;
using std::unique_ptr;

class MerkleTreeLargeTest : public ::testing::Test {
 protected:
  string data_;
  MerkleTreeLargeTest() : data_(string(1024, 0x42)) {
  }
};

TEST_F(MerkleTreeLargeTest, BuildLargeTree) {
  std::vector<MerkleTree*> trees;
  for (size_t tree_size = 1024; tree_size <= 4194304; tree_size *= 4) {
    LOG(WARNING) << "Building a tree with " << tree_size << " leaves";

    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    long max_rss_before = ru.ru_maxrss;
    MerkleTree* tree(
        new MerkleTree(unique_ptr<Sha256Hasher>(new Sha256Hasher)));
    trees.push_back(tree);
    uint64_t time_before = util::TimeInMilliseconds();

    for (size_t i = 0; i < tree_size; ++i)
      tree->AddLeaf(data_);
    EXPECT_FALSE(tree->CurrentRoot().empty());
    EXPECT_TRUE(tree->LeafCount() == tree_size);
    getrusage(RUSAGE_SELF, &ru);
    uint64_t time_after = util::TimeInMilliseconds();

    LOG(WARNING) << "Peak RSS delta (as reported by getrusage()) was "
                 << ru.ru_maxrss - max_rss_before << " kB";

    LOG(WARNING) << "Elapsed time: " << time_after - time_before << " ms";
  }

  for (size_t i = 0; i < trees.size(); ++i) {
    EXPECT_FALSE(trees[i]->CurrentRoot().empty());
    delete trees[i];
  }
}

}  // namespace

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
