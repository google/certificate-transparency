#include "log/cluster_state_controller.h"

#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>
#include <thread>

#include "log/logged_certificate.h"
#include "proto/ct.pb.h"
#include "util/fake_etcd.h"
#include "util/libevent_wrapper.h"
#include "util/mock_masterelection.h"
#include "util/testing.h"
#include "util/util.h"

using ct::ClusterConfig;
using ct::ClusterNodeState;
using ct::SignedTreeHead;
using std::make_shared;
using std::shared_ptr;
using std::string;
using testing::Return;
using testing::NiceMock;
using util::StatusOr;

namespace cert_trans {

const char kNodeId1[] = "node1";
const char kNodeId2[] = "node2";
const char kNodeId3[] = "node3";


class ClusterStateControllerTest : public ::testing::Test {
 public:
  ClusterStateControllerTest()
      : pool_(2),
        base_(make_shared<libevent::Base>()),
        pump_(base_),
        etcd_(base_),
        store1_(new EtcdConsistentStore<LoggedCertificate>(&pool_, &etcd_,
                                                           &election1_, "",
                                                           kNodeId1)),
        store2_(new EtcdConsistentStore<LoggedCertificate>(&pool_, &etcd_,
                                                           &election2_, "",
                                                           kNodeId2)),
        store3_(new EtcdConsistentStore<LoggedCertificate>(&pool_, &etcd_,
                                                           &election3_, "",
                                                           kNodeId3)),
        controller_(&pool_, store1_.get(), &election1_) {
    // Set default cluster config:
    ct::ClusterConfig default_config;
    default_config.set_minimum_serving_nodes(1);
    default_config.set_minimum_serving_fraction(1);
    store1_->SetClusterConfig(default_config);

    // Set up some handy STHs
    sth100_.set_tree_size(100);
    sth100_.set_timestamp(100);
    sth200_.set_tree_size(200);
    sth200_.set_timestamp(200);
    sth300_.set_tree_size(300);
    sth300_.set_timestamp(300);
    cns100_.mutable_newest_sth()->CopyFrom(sth100_);
    cns200_.mutable_newest_sth()->CopyFrom(sth200_);
    cns300_.mutable_newest_sth()->CopyFrom(sth300_);
  }

 protected:
  ct::ClusterNodeState GetLocalState() {
    return controller_.local_node_state_;
  }

  ct::ClusterNodeState GetNodeStateView(const string& node_id) {
    auto it(controller_.all_node_states_.find(node_id));
    CHECK(it != controller_.all_node_states_.end());
    return it->second;
  }

  static void SetClusterConfig(ConsistentStore<LoggedCertificate>* store,
                               const int min_nodes,
                               const double min_fraction) {
    ClusterConfig config;
    config.set_minimum_serving_nodes(min_nodes);
    config.set_minimum_serving_fraction(min_fraction);
    CHECK(store->SetClusterConfig(config).ok());
  }


  SignedTreeHead sth100_, sth200_, sth300_;
  ClusterNodeState cns100_, cns200_, cns300_;

  ThreadPool pool_;
  shared_ptr<libevent::Base> base_;
  libevent::EventPumpThread pump_;
  FakeEtcdClient etcd_;
  NiceMock<MockMasterElection> election1_;
  NiceMock<MockMasterElection> election2_;
  NiceMock<MockMasterElection> election3_;
  std::unique_ptr<EtcdConsistentStore<LoggedCertificate>> store1_;
  std::unique_ptr<EtcdConsistentStore<LoggedCertificate>> store2_;
  std::unique_ptr<EtcdConsistentStore<LoggedCertificate>> store3_;
  ClusterStateController<LoggedCertificate> controller_;
};


typedef class EtcdConsistentStoreTest EtcdConsistentStoreDeathTest;


TEST_F(ClusterStateControllerTest, TestNewTreeHead) {
  ct::SignedTreeHead sth;
  sth.set_tree_size(234);
  controller_.NewTreeHead(sth);
  EXPECT_EQ(sth.DebugString(), GetLocalState().newest_sth().DebugString());
}


TEST_F(ClusterStateControllerTest, TestContiguousTreeSizeUpdated) {
  const int kNewTreeSize(2345);
  controller_.ContiguousTreeSizeUpdated(kNewTreeSize);
  EXPECT_EQ(kNewTreeSize, GetLocalState().contiguous_tree_size());
}


TEST_F(ClusterStateControllerTest, TestCalculateServingSTHAt50Percent) {
  MockMasterElection election_is_master;
  EXPECT_CALL(election_is_master, IsMaster()).WillRepeatedly(Return(true));
  ClusterStateController<LoggedCertificate> controller50(&pool_, store1_.get(),
                                                         &election_is_master);
  SetClusterConfig(store1_.get(), 1 /* nodes */, 0.5 /* fraction */);

  store1_->SetClusterNodeState(cns100_);
  sleep(1);
  util::StatusOr<SignedTreeHead> sth(controller50.GetCalculatedServingSTH());
  // Can serve sth1 because all nodes have it !
  EXPECT_EQ(sth100_.tree_size(), sth.ValueOrDie().tree_size());

  store2_->SetClusterNodeState(cns200_);
  sleep(1);
  // Can serve sth2 because 50% of nodes have it
  sth = controller50.GetCalculatedServingSTH();
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());

  store3_->SetClusterNodeState(cns300_);
  sleep(1);
  // Can serve sth2 because 66% of nodes have it (or higher)
  // Can't serve sth3 because only 33% of nodes cover it.
  sth = controller50.GetCalculatedServingSTH();
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());
}


TEST_F(ClusterStateControllerTest, TestCalculateServingSTHAt70Percent) {
  MockMasterElection election_is_master;
  EXPECT_CALL(election_is_master, IsMaster()).WillRepeatedly(Return(true));
  ClusterStateController<LoggedCertificate> controller70(&pool_, store1_.get(),
                                                         &election_is_master);
  SetClusterConfig(store1_.get(), 1 /* nodes */, 0.7 /* fraction */);
  store1_->SetClusterNodeState(cns100_);
  sleep(1);
  util::StatusOr<SignedTreeHead> sth(controller70.GetCalculatedServingSTH());
  // Can serve sth1 because all nodes have it !
  EXPECT_EQ(sth100_.tree_size(), sth.ValueOrDie().tree_size());

  store2_->SetClusterNodeState(cns200_);
  sleep(1);
  // Can still only serve sth1 because only 50% of nodes have sth2
  sth = controller70.GetCalculatedServingSTH();
  EXPECT_EQ(sth100_.tree_size(), sth.ValueOrDie().tree_size());

  store3_->SetClusterNodeState(cns300_);
  sleep(1);
  // Can still only serve sth1 because only 66% of nodes have sth2
  sth = controller70.GetCalculatedServingSTH();
  EXPECT_EQ(sth100_.tree_size(), sth.ValueOrDie().tree_size());
}


TEST_F(ClusterStateControllerTest,
       TestCalculateServingSTHAt60PercentTwoNodeMin) {
  MockMasterElection election_is_master;
  EXPECT_CALL(election_is_master, IsMaster()).WillRepeatedly(Return(true));
  ClusterStateController<LoggedCertificate> controller60(&pool_, store1_.get(),
                                                         &election_is_master);
  SetClusterConfig(store1_.get(), 2 /* nodes */, 0.6 /* fraction */);
  store1_->SetClusterNodeState(cns100_);
  sleep(1);
  util::StatusOr<SignedTreeHead> sth(controller60.GetCalculatedServingSTH());
  // Can't serve at all because not enough nodes
  EXPECT_FALSE(sth.ok());

  store2_->SetClusterNodeState(cns200_);
  sleep(1);
  // Can serve sth1 because there are two nodes, but < 60% coverage for sth2
  sth = controller60.GetCalculatedServingSTH();
  EXPECT_EQ(sth100_.tree_size(), sth.ValueOrDie().tree_size());

  store3_->SetClusterNodeState(cns300_);
  sleep(1);
  sth = controller60.GetCalculatedServingSTH();
  // Can serve sth2 because there are two out of three nodes with sth2 or above
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());
}


TEST_F(ClusterStateControllerTest, TestCalculateServingSTHAsClusterMoves) {
  MockMasterElection election_is_master;
  EXPECT_CALL(election_is_master, IsMaster()).WillRepeatedly(Return(true));
  ClusterStateController<LoggedCertificate> controller50(&pool_, store1_.get(),
                                                         &election_is_master);
  SetClusterConfig(store1_.get(), 1 /* nodes */, 0.5 /* fraction */);
  store1_->SetClusterNodeState(cns100_);
  store2_->SetClusterNodeState(cns100_);
  store3_->SetClusterNodeState(cns100_);
  sleep(1);
  util::StatusOr<SignedTreeHead> sth(controller50.GetCalculatedServingSTH());
  EXPECT_EQ(sth100_.tree_size(), sth.ValueOrDie().tree_size());

  store1_->SetClusterNodeState(cns200_);
  sleep(1);
  // Node1@200
  // Node2 and Node3 @100:
  // Still have to serve at sth100
  sth = controller50.GetCalculatedServingSTH();
  EXPECT_EQ(sth100_.tree_size(), sth.ValueOrDie().tree_size());

  store3_->SetClusterNodeState(cns200_);
  sleep(1);
  // Node1 and Node3 @200
  // Node2 @100:
  // Can serve at sth200
  sth = controller50.GetCalculatedServingSTH();
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());

  store2_->SetClusterNodeState(cns300_);
  sleep(1);
  // Node1 and Node3 @200
  // Node2 @300:
  // Still have to serve at sth200
  sth = controller50.GetCalculatedServingSTH();
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());
}


TEST_F(ClusterStateControllerTest, TestKeepsNewerSTH) {
  store1_->SetClusterNodeState(cns100_);

  // Create a node with an identically sized but newer STH:
  SignedTreeHead newer_sth(sth100_);
  newer_sth.set_timestamp(newer_sth.timestamp() + 1);
  ClusterNodeState newer_cns;
  *newer_cns.mutable_newest_sth() = newer_sth;
  store2_->SetClusterNodeState(newer_cns);
  sleep(1);

  util::StatusOr<SignedTreeHead> sth(controller_.GetCalculatedServingSTH());
  EXPECT_EQ(newer_sth.tree_size(), sth.ValueOrDie().tree_size());
  EXPECT_EQ(newer_sth.timestamp(), sth.ValueOrDie().timestamp());
}


TEST_F(ClusterStateControllerTest, TestCannotSelectSmallerSTH) {
  MockMasterElection election_is_master;
  EXPECT_CALL(election_is_master, IsMaster()).WillRepeatedly(Return(true));
  ClusterStateController<LoggedCertificate> controller50(&pool_, store1_.get(),
                                                         &election_is_master);
  SetClusterConfig(store1_.get(), 1 /* nodes */, 0.5 /* fraction */);
  store1_->SetClusterNodeState(cns200_);
  store2_->SetClusterNodeState(cns200_);
  store3_->SetClusterNodeState(cns200_);
  sleep(1);
  util::StatusOr<SignedTreeHead> sth(controller50.GetCalculatedServingSTH());
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());

  store1_->SetClusterNodeState(cns100_);
  sleep(1);
  // Node1@100
  // Node2 and Node3 @200:
  // Still have to serve at sth200
  sth = controller50.GetCalculatedServingSTH();
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());

  store3_->SetClusterNodeState(cns100_);
  sleep(1);
  // Node1 and Node3 @100
  // Node2 @200
  // But cannot select an earlier STH than the one we last served with, so must
  // stick with sth200:
  sth = controller50.GetCalculatedServingSTH();
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());

  store2_->SetClusterNodeState(cns100_);
  sleep(1);
  // Still have to serve at sth200
  sth = controller50.GetCalculatedServingSTH();
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());
}


TEST_F(ClusterStateControllerTest,
       TestConfigChangesCauseServingSTHToBeRecalculated) {
  MockMasterElection election_is_master;
  EXPECT_CALL(election_is_master, IsMaster()).WillRepeatedly(Return(true));
  ClusterStateController<LoggedCertificate> controller(&pool_, store1_.get(),
                                                       &election_is_master);
  SetClusterConfig(store1_.get(), 0 /* nodes */, 0.5 /* fraction */);
  store1_->SetClusterNodeState(cns100_);
  store2_->SetClusterNodeState(cns200_);
  store3_->SetClusterNodeState(cns300_);
  sleep(1);
  StatusOr<SignedTreeHead> sth(controller.GetCalculatedServingSTH());
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());

  SetClusterConfig(store1_.get(), 0 /* nodes */, 0.9 /* fraction */);
  sleep(1);
  sth = controller.GetCalculatedServingSTH();
  // You might expect sth100 here, but we shouldn't move to a smaller STH
  EXPECT_EQ(sth200_.tree_size(), sth.ValueOrDie().tree_size());

  SetClusterConfig(store1_.get(), 0 /* nodes */, 0.3 /* fraction */);
  sleep(1);
  sth = controller.GetCalculatedServingSTH();
  // Should be able to move to sth300 now.
  EXPECT_EQ(sth300_.tree_size(), sth.ValueOrDie().tree_size());
}


TEST_F(ClusterStateControllerTest, TestGetLocalNodeState) {
  const int kContiguousSize(2345);
  SignedTreeHead sth;
  sth.set_timestamp(10000);
  sth.set_tree_size(2344);
  controller_.NewTreeHead(sth);
  controller_.ContiguousTreeSizeUpdated(kContiguousSize);

  ClusterNodeState state;
  controller_.GetLocalNodeState(&state);
  EXPECT_EQ(kContiguousSize, state.contiguous_tree_size());
  EXPECT_EQ(sth.DebugString(), state.newest_sth().DebugString());
}


TEST_F(ClusterStateControllerTest, TestLeavesElectionIfDoesNotHaveLocalData) {
  const int kContiguousSize(2345);
  const int kTreeSizeSmaller(kContiguousSize - 1);
  const int kTreeSizeLarger(kContiguousSize + 1);

  controller_.ContiguousTreeSizeUpdated(kContiguousSize);
  sleep(1);

  SignedTreeHead sth;
  {
    EXPECT_CALL(election1_, StartElection()).Times(1);
    sth.set_timestamp(10000);
    sth.set_tree_size(kTreeSizeSmaller);
    store1_->SetServingSTH(sth);
    sleep(1);
  }

  {
    EXPECT_CALL(election1_, StopElection()).Times(1);
    sth.set_timestamp(sth.timestamp() + 1);
    sth.set_tree_size(kTreeSizeLarger);
    store1_->SetServingSTH(sth);
    sleep(1);
  }
}


TEST_F(ClusterStateControllerTest, TestJoinsElectionIfHasLocalData) {
  const int kContiguousSizeSmaller(2345);
  const int kTreeSize(kContiguousSizeSmaller + 1);
  const int kContiguousSizeLarger(kTreeSize + 1);

  controller_.ContiguousTreeSizeUpdated(kContiguousSizeSmaller);
  SignedTreeHead sth;
  sth.set_timestamp(10000);
  sth.set_tree_size(kTreeSize);
  store1_->SetServingSTH(sth);
  sleep(1);

  {
    EXPECT_CALL(election1_, StartElection()).Times(1);
    controller_.ContiguousTreeSizeUpdated(kContiguousSizeLarger);
    sleep(1);
  }
}


TEST_F(ClusterStateControllerTest, TestNodeHostPort) {
  const string kHost("my_host");
  const int kPort(9999);
  controller_.SetNodeHostPort(kHost, kPort);
  sleep(1);

  const ClusterNodeState node_state(GetNodeStateView(kNodeId1));
  EXPECT_EQ(kHost, node_state.hostname());
  EXPECT_EQ(kPort, node_state.log_port());
}


}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
