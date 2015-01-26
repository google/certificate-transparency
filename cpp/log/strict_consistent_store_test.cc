#include "log/strict_consistent_store.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "log/logged_certificate.h"
#include "log/mock_consistent_store.h"
#include "util/mock_masterelection.h"
#include "util/status.h"
#include "util/statusor.h"
#include "util/testing.h"
#include "util/util.h"

DECLARE_int32(node_state_ttl_seconds);

namespace cert_trans {

using testing::_;
using testing::NiceMock;
using testing::Return;
using util::Status;
using util::StatusOr;


class StrictConsistentStoreTest : public ::testing::TestWithParam<bool> {
 public:
  StrictConsistentStoreTest()
      : peer_(new NiceMock<MockConsistentStore<LoggedCertificate>>()),
        strict_store_(&election_, peer_) {
    ON_CALL(election_, IsMaster()).WillByDefault(Return(IsMaster()));
  }

 protected:
  bool IsMaster() const {
    return GetParam();
  }

  NiceMock<MockMasterElection> election_;
  // strict_store_ takes ownership of this:
  NiceMock<MockConsistentStore<LoggedCertificate>>* peer_;
  StrictConsistentStore<LoggedCertificate> strict_store_;
};


TEST_P(StrictConsistentStoreTest, TestNextAvailableSequenceNumber) {
  if (IsMaster()) {
    EXPECT_CALL(*peer_, NextAvailableSequenceNumber()).WillOnce(Return(123));
  } else {
    EXPECT_CALL(*peer_, NextAvailableSequenceNumber()).Times(0);
  }

  util::StatusOr<int64_t> seq(strict_store_.NextAvailableSequenceNumber());

  if (IsMaster()) {
    EXPECT_EQ(123, seq.ValueOrDie());
  } else {
    EXPECT_FALSE(seq.ok());
    EXPECT_EQ(util::error::PERMISSION_DENIED, seq.status().CanonicalCode());
  }
}


TEST_P(StrictConsistentStoreTest, TestSetServingSTH) {
  if (IsMaster()) {
    EXPECT_CALL(*peer_, SetServingSTH(_)).WillOnce(Return(util::Status::OK));
  } else {
    EXPECT_CALL(*peer_, SetServingSTH(_)).Times(0);
  }

  ct::SignedTreeHead sth;
  sth.set_timestamp(234);
  util::Status status(strict_store_.SetServingSTH(sth));

  if (IsMaster()) {
    EXPECT_TRUE(status.ok());
  } else {
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(util::error::PERMISSION_DENIED, status.CanonicalCode());
  }
}


TEST_P(StrictConsistentStoreTest, TestAssignSequenceNumber) {
  if (IsMaster()) {
    EXPECT_CALL(*peer_, AssignSequenceNumber(_, _))
        .WillOnce(Return(util::Status::OK));
  } else {
    EXPECT_CALL(*peer_, AssignSequenceNumber(_, _)).Times(0);
  }

  EntryHandle<LoggedCertificate> cert;
  util::Status status(strict_store_.AssignSequenceNumber(7, &cert));

  if (IsMaster()) {
    EXPECT_TRUE(status.ok());
  } else {
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(util::error::PERMISSION_DENIED, status.CanonicalCode());
  }
}


TEST_P(StrictConsistentStoreTest, TestClusterConfig) {
  if (IsMaster()) {
    EXPECT_CALL(*peer_, SetClusterConfig(_))
        .WillOnce(Return(util::Status::OK));
  } else {
    EXPECT_CALL(*peer_, SetClusterConfig(_)).Times(0);
  }

  ct::ClusterConfig conf;
  util::Status status(strict_store_.SetClusterConfig(conf));

  if (IsMaster()) {
    EXPECT_TRUE(status.ok());
  } else {
    EXPECT_FALSE(status.ok());
    EXPECT_EQ(util::error::PERMISSION_DENIED, status.CanonicalCode());
  }
}


INSTANTIATE_TEST_CASE_P(MasterInstance, StrictConsistentStoreTest,
                        testing::Values(true, false));


}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
