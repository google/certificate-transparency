#include "log/etcd_consistent_store.h"

#include <atomic>
#include <functional>
#include <gmock/gmock.h>
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

DECLARE_int32(node_state_ttl_seconds);

namespace cert_trans {


using ct::SignedTreeHead;
using std::atomic;
using std::bind;
using std::chrono::milliseconds;
using std::make_shared;
using std::pair;
using std::placeholders::_1;
using std::shared_ptr;
using std::string;
using std::thread;
using std::unique_ptr;
using std::vector;
using testing::_;
using testing::AllOf;
using testing::ContainerEq;
using testing::Contains;
using testing::Pair;
using testing::Return;
using testing::SetArgumentPointee;
using util::Status;
using util::SyncTask;


const char kRoot[] = "/root";
const char kNodeId[] = "node_id";
const int kTimestamp = 9000;


class EtcdConsistentStoreTest : public ::testing::Test {
 public:
  EtcdConsistentStoreTest()
      : base_(make_shared<libevent::Base>()),
        executor_(1),
        event_pump_(base_),
        client_(base_),
        sync_client_(&client_) {
  }

 protected:
  void SetUp() override {
    store_.reset(new EtcdConsistentStore<LoggedCertificate>(
        &executor_, &client_, &election_, kRoot, kNodeId));
  }

  LoggedCertificate DefaultCert() {
    return MakeCert(kTimestamp, "leaf");
  }

  LoggedCertificate MakeCert(int timestamp, const string& body) {
    LoggedCertificate cert;
    cert.mutable_sct()->set_timestamp(timestamp);
    cert.mutable_entry()->set_type(ct::X509_ENTRY);
    cert.mutable_entry()->mutable_x509_entry()->set_leaf_certificate(body);
    return cert;
  }

  LoggedCertificate MakeSequencedCert(int timestamp, const string& body,
                                      int seq) {
    LoggedCertificate cert(MakeCert(timestamp, body));
    cert.set_sequence_number(seq);
    return cert;
  }

  EntryHandle<LoggedCertificate> HandleForCert(const LoggedCertificate& cert) {
    return EntryHandle<LoggedCertificate>(cert);
  }

  EntryHandle<LoggedCertificate> HandleForCert(const LoggedCertificate& cert,
                                               int handle) {
    return EntryHandle<LoggedCertificate>(cert, handle);
  }

  void PopulateForCleanupTests(int num_seq, int num_unseq, int starting_seq) {
    int timestamp(345345);
    int seq(starting_seq);
    for (int i = 0; i < num_seq; ++i) {
      std::ostringstream ss;
      ss << "sequenced body " << i;
      LoggedCertificate lc(MakeCert(timestamp++, ss.str()));
      CHECK(store_->AddPendingEntry(&lc).ok());
      EntryHandle<LoggedCertificate> handle;
      CHECK(store_->GetPendingEntryForHash(lc.Hash(), &handle).ok());
      CHECK(store_->AssignSequenceNumber(seq++, &handle).ok());
    }
    for (int i = 0; i < num_unseq; ++i) {
      std::ostringstream ss;
      ss << "unsequenced body " << i;
      LoggedCertificate lc(MakeCert(timestamp++, ss.str()));
      CHECK(store_->AddPendingEntry(&lc).ok());
    }
  }

  util::Status RunOneCleanUpIteration(int clean_up_to_seq) {
    return store_->RunOneCleanUpIteration(clean_up_to_seq);
  }

  template <class T>
  void InsertEntry(const string& key, const T& thing) {
    // Set up scenario:
    int64_t index;
    Status status(sync_client_.Create(key, Serialize(thing), &index));
    ASSERT_TRUE(status.ok()) << status;
  }

  template <class T>
  void PeekEntry(const string& key, T* thing) {
    EtcdClient::Node node;
    Status status(sync_client_.Get(key, &node));
    ASSERT_TRUE(status.ok()) << status;
    Deserialize(node.value_, thing);
  }

  template <class T>
  string Serialize(const T& t) {
    string flat;
    t.SerializeToString(&flat);
    return util::ToBase64(flat);
  }

  template <class T>
  void Deserialize(const string& flat, T* t) {
    ASSERT_TRUE(t->ParseFromString(util::FromBase64(flat.c_str())));
  }

  template <class T>
  EtcdClient::Node NodeFor(const int index, const std::string& key,
                           const T& t) {
    return EtcdClient::Node(index, index, key, Serialize(t));
  }

  ct::SignedTreeHead ServingSTH() {
    return store_->serving_sth_->Entry();
  }

  shared_ptr<libevent::Base> base_;
  ThreadPool executor_;
  libevent::EventPumpThread event_pump_;
  FakeEtcdClient client_;
  SyncEtcdClient sync_client_;
  MockMasterElection election_;
  unique_ptr<EtcdConsistentStore<LoggedCertificate>> store_;
};


typedef class EtcdConsistentStoreTest EtcdConsistentStoreDeathTest;


TEST_F(
    EtcdConsistentStoreDeathTest,
    TestNextAvailableSequenceNumberWhenNoSequencedEntriesOrServingSTHExist) {
  EXPECT_EQ(0, store_->NextAvailableSequenceNumber().ValueOrDie());
}


TEST_F(EtcdConsistentStoreTest,
       TestNextAvailableSequenceNumberWhenSequencedEntriesExist) {
  const LoggedCertificate one(MakeSequencedCert(0, "one", 1));
  const LoggedCertificate two(MakeSequencedCert(1, "two", 1));
  InsertEntry(string(kRoot) + "/sequenced/0", one);
  InsertEntry(string(kRoot) + "/sequenced/1", two);

  EXPECT_EQ(2, store_->NextAvailableSequenceNumber().ValueOrDie());
}


TEST_F(EtcdConsistentStoreTest,
       TestNextAvailableSequenceNumberWhenNoSequencedEntriesExistButHaveSTH) {
  ct::SignedTreeHead serving_sth;
  serving_sth.set_timestamp(123);
  serving_sth.set_tree_size(600);
  EXPECT_TRUE(store_->SetServingSTH(serving_sth).ok());

  EXPECT_EQ(serving_sth.tree_size(),
            store_->NextAvailableSequenceNumber().ValueOrDie());
}


TEST_F(EtcdConsistentStoreTest, TestSetServingSTH) {
  ct::SignedTreeHead sth;
  util::Status status(store_->SetServingSTH(sth));
  EXPECT_TRUE(status.ok()) << status;
}


TEST_F(EtcdConsistentStoreTest, TestSetServingSTHOverwrites) {
  ct::SignedTreeHead sth;
  sth.set_timestamp(234);
  util::Status status(store_->SetServingSTH(sth));
  EXPECT_TRUE(status.ok()) << status;

  ct::SignedTreeHead sth2;
  sth2.set_timestamp(sth.timestamp() + 1);
  status = store_->SetServingSTH(sth2);
  EXPECT_TRUE(status.ok()) << status;
}


TEST_F(EtcdConsistentStoreTest, TestSetServingSTHWontOverwriteWithOlder) {
  ct::SignedTreeHead sth;
  sth.set_timestamp(234);
  util::Status status(store_->SetServingSTH(sth));
  EXPECT_TRUE(status.ok()) << status;

  ct::SignedTreeHead sth2;
  sth2.set_timestamp(sth.timestamp() - 1);
  status = store_->SetServingSTH(sth2);
  EXPECT_EQ(util::error::OUT_OF_RANGE, status.CanonicalCode()) << status;
}


TEST_F(EtcdConsistentStoreDeathTest, TestSetServingSTHChecksInconsistentSize) {
  ct::SignedTreeHead sth;
  sth.set_timestamp(234);
  sth.set_tree_size(10);
  util::Status status(store_->SetServingSTH(sth));
  EXPECT_TRUE(status.ok()) << status;

  ct::SignedTreeHead sth2;
  // newer STH...
  sth2.set_timestamp(sth.timestamp() + 1);
  // but. curiously, a smaller tree...
  sth2.set_tree_size(sth.tree_size() - 1);
  EXPECT_DEATH(store_->SetServingSTH(sth2), "tree_size");
}


TEST_F(EtcdConsistentStoreTest, TestAddPendingEntryWorks) {
  LoggedCertificate cert(DefaultCert());
  util::Status status(store_->AddPendingEntry(&cert));
  ASSERT_TRUE(status.ok()) << status;
  EtcdClient::Node node;
  status = sync_client_.Get(string(kRoot) + "/unsequenced/" +
                                util::ToBase64(cert.Hash()),
                            &node);
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(Serialize(cert), node.value_);
}


TEST_F(EtcdConsistentStoreTest,
       TestAddPendingEntryForExistingEntryReturnsSct) {
  LoggedCertificate cert(DefaultCert());
  LoggedCertificate other_cert(DefaultCert());
  other_cert.mutable_sct()->set_timestamp(55555);

  const string kKey(util::ToBase64(cert.Hash()));
  const string kPath(string(kRoot) + "/unsequenced/" + kKey);
  // Set up scenario:
  InsertEntry(kPath, other_cert);

  util::Status status(store_->AddPendingEntry(&cert));
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.CanonicalCode());
  EXPECT_EQ(other_cert.timestamp(), cert.timestamp());
}


TEST_F(EtcdConsistentStoreDeathTest,
       TestAddPendingEntryForExistingNonIdenticalEntry) {
  LoggedCertificate cert(DefaultCert());
  LoggedCertificate other_cert(MakeCert(2342, "something else"));

  const string kKey(util::ToBase64(cert.Hash()));
  const string kPath(string(kRoot) + "/unsequenced/" + kKey);
  // Set up scenario:
  InsertEntry(kPath, other_cert);

  EXPECT_DEATH(store_->AddPendingEntry(&cert),
               "Check failed: LeafEntriesMatch");
}


TEST_F(EtcdConsistentStoreDeathTest,
       TestAddPendingEntryDoesNotAcceptSequencedEntry) {
  LoggedCertificate cert(DefaultCert());
  cert.set_sequence_number(76);
  EXPECT_DEATH(store_->AddPendingEntry(&cert),
               "!entry\\->has_sequence_number");
}


TEST_F(EtcdConsistentStoreTest, TestGetPendingEntryForHash) {
  const LoggedCertificate one(MakeCert(123, "one"));
  const string kPath(string(kRoot) + "/unsequenced/" +
                     util::ToBase64(one.Hash()));
  InsertEntry(kPath, one);

  EntryHandle<LoggedCertificate> handle;
  util::Status status(store_->GetPendingEntryForHash(one.Hash(), &handle));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(one, handle.Entry());
  EXPECT_EQ(1, handle.Handle());
}


TEST_F(EtcdConsistentStoreTest, TestGetPendingEntryForNonExistantHash) {
  const string kPath(string(kRoot) + "/unsequenced/" + util::ToBase64("Nah"));
  EntryHandle<LoggedCertificate> handle;
  util::Status status(store_->GetPendingEntryForHash("Nah", &handle));
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(EtcdConsistentStoreTest, TestGetPendingEntries) {
  const string kPath(string(kRoot) + "/unsequenced/");
  const LoggedCertificate one(MakeCert(123, "one"));
  const LoggedCertificate two(MakeCert(456, "two"));
  InsertEntry(kPath + "one", one);
  InsertEntry(kPath + "two", two);

  vector<EntryHandle<LoggedCertificate>> entries;
  util::Status status(store_->GetPendingEntries(&entries));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(2, entries.size());
  vector<LoggedCertificate> certs;
  for (const auto& e : entries) {
    certs.push_back(e.Entry());
  }
  EXPECT_THAT(certs, AllOf(Contains(one), Contains(two)));
}


TEST_F(EtcdConsistentStoreDeathTest,
       TestGetPendingEntriesBarfsWithSequencedEntry) {
  const string kPath(string(kRoot) + "/unsequenced/");
  LoggedCertificate one(MakeSequencedCert(123, "one", 666));
  InsertEntry(kPath + "one", one);
  vector<EntryHandle<LoggedCertificate>> entries;
  EXPECT_DEATH(store_->GetPendingEntries(&entries), "has_sequence_number");
}


TEST_F(EtcdConsistentStoreTest, TestGetSequencedEntries) {
  const string kPath(string(kRoot) + "/sequenced/");
  const LoggedCertificate one(MakeSequencedCert(123, "one", 1));
  const LoggedCertificate two(MakeSequencedCert(456, "two", 2));
  InsertEntry(kPath + "one", one);
  InsertEntry(kPath + "two", two);
  vector<EntryHandle<LoggedCertificate>> entries;
  util::Status status(store_->GetSequencedEntries(&entries));
  EXPECT_EQ(2, entries.size());
  vector<LoggedCertificate> certs;
  for (const auto& e : entries) {
    certs.push_back(e.Entry());
  }
  EXPECT_THAT(certs, AllOf(Contains(one), Contains(two)));
}


TEST_F(EtcdConsistentStoreDeathTest,
       TestGetSequencedEntriesBarfsWitUnsSequencedEntry) {
  const string kPath(string(kRoot) + "/sequenced/");
  LoggedCertificate one(MakeCert(123, "one"));
  InsertEntry(kPath + "one", one);
  vector<EntryHandle<LoggedCertificate>> entries;
  EXPECT_DEATH(store_->GetSequencedEntries(&entries), "has_sequence_number");
}


TEST_F(EtcdConsistentStoreTest, TestAssignSequenceNumber) {
  const int kDefaultHandle(1);
  EntryHandle<LoggedCertificate> entry(
      HandleForCert(DefaultCert(), kDefaultHandle));

  const string kUnsequencedPath(string(kRoot) + "/unsequenced/" +
                                util::ToBase64(entry.Entry().Hash()));
  const string kSequencedPath(string(kRoot) + "/sequenced/1");
  const int kSeq(1);


  LoggedCertificate entry_with_provisional(entry.Entry());
  entry_with_provisional.set_provisional_sequence_number(kSeq);
  InsertEntry(kUnsequencedPath, entry_with_provisional);

  util::Status status(store_->AssignSequenceNumber(kSeq, &entry));
  EXPECT_TRUE(status.ok()) << status;
}


TEST_F(EtcdConsistentStoreDeathTest,
       TestAssignSequenceNumberBarfsWithSequencedEntry) {
  EntryHandle<LoggedCertificate> entry(
      HandleForCert(MakeSequencedCert(123, "hi", 44)));
  EXPECT_DEATH(util::Status status(store_->AssignSequenceNumber(1, &entry));
               , "has_sequence_number");
}


TEST_F(EtcdConsistentStoreDeathTest,
       TestAssignSequenceNumberBarfsWithMismatchedSequencedEntry) {
  EntryHandle<LoggedCertificate> entry(HandleForCert(MakeCert(123, "hi")));
  entry.MutableEntry()->set_provisional_sequence_number(257);
  EXPECT_DEATH(util::Status status(store_->AssignSequenceNumber(1, &entry));
               , "sequence_number ==.*provisional.*");
}


TEST_F(EtcdConsistentStoreTest, TestSetClusterNodeState) {
  const string kPath(string(kRoot) + "/nodes/" + kNodeId);

  ct::ClusterNodeState state;
  state.set_node_id(kNodeId);

  util::Status status(store_->SetClusterNodeState(state));
  EXPECT_TRUE(status.ok()) << status;

  ct::ClusterNodeState set_state;
  PeekEntry(kPath, &set_state);
  EXPECT_EQ(state.node_id(), set_state.node_id());
}


TEST_F(EtcdConsistentStoreTest, TestSetClusterNodeStateHasTTL) {
  FLAGS_node_state_ttl_seconds = 1;
  const string kPath(string(kRoot) + "/nodes/" + kNodeId);

  ct::ClusterNodeState state;
  state.set_node_id(kNodeId);

  util::Status status(store_->SetClusterNodeState(state));
  EXPECT_TRUE(status.ok()) << status;

  ct::ClusterNodeState set_state;
  PeekEntry(kPath, &set_state);
  EXPECT_EQ(state.node_id(), set_state.node_id());

  sleep(2);

  EtcdClient::Node node;
  status = sync_client_.Get(kPath, &node);
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode());
}


TEST_F(EtcdConsistentStoreTest, WatchServingSTH) {
  Notification notify;

  const string kPath(string(kRoot) + "/serving_sth");

  ct::SignedTreeHead sth;
  sth.set_timestamp(234234);

  SyncTask task(&executor_);
  store_->WatchServingSTH(
      [&sth, &notify](const Update<ct::SignedTreeHead>& update) {
        static int call_count(0);
        switch (call_count) {
          case 0:
            // initial empty state
            EXPECT_FALSE(update.exists_);
            break;
          case 1:
            // notification of update
            EXPECT_TRUE(update.exists_);
            EXPECT_EQ(sth.DebugString(), update.handle_.Entry().DebugString());
            notify.Notify();
            break;
          default:
            CHECK(false);
        }
        ++call_count;
      },
      task.task());

  util::Status status(store_->SetServingSTH(sth));
  EXPECT_TRUE(status.ok()) << status;
  notify.WaitForNotification();
  EXPECT_EQ(ServingSTH().DebugString(), sth.DebugString());
  task.Cancel();
  task.Wait();
}


TEST_F(EtcdConsistentStoreTest, WatchClusterNodeStates) {
  const string kPath(string(kRoot) + "/nodes/" + kNodeId);

  ct::ClusterNodeState state;
  state.set_node_id(kNodeId);

  SyncTask task(&executor_);
  store_->WatchClusterNodeStates(
      [&state](const vector<Update<ct::ClusterNodeState>>& updates) {
        if (updates.empty()) {
          VLOG(1) << "Ignoring initial empty update.";
          return;
        }
        EXPECT_TRUE(updates[0].exists_);
        EXPECT_EQ(updates[0].handle_.Entry().DebugString(),
                  state.DebugString());
      },
      task.task());
  util::Status status(store_->SetClusterNodeState(state));
  EXPECT_TRUE(status.ok()) << status;
  task.Cancel();
  task.Wait();
}


TEST_F(EtcdConsistentStoreTest, WatchClusterConfig) {
  const string kPath(string(kRoot) + "/cluster_config");

  ct::ClusterConfig config;
  config.set_minimum_serving_nodes(1);
  config.set_minimum_serving_fraction(0.6);
  Notification notification;

  SyncTask task(&executor_);
  store_->WatchClusterConfig(
      [&config, &notification](const Update<ct::ClusterConfig>& update) {
        if (!update.exists_) {
          VLOG(1) << "Ignoring initial empty update.";
          return;
        }
        EXPECT_TRUE(update.exists_);
        EXPECT_EQ(update.handle_.Entry().DebugString(), config.DebugString());
        notification.Notify();
      },
      task.task());
  util::Status status(store_->SetClusterConfig(config));
  EXPECT_TRUE(status.ok()) << status;
  // Make sure we got called from the watcher:
  EXPECT_TRUE(notification.WaitForNotificationWithTimeout(milliseconds(5000)));
  task.Cancel();
  task.Wait();
}


TEST_F(EtcdConsistentStoreTest, TestDoesNotCleanUpIfNotMaster) {
  EXPECT_CALL(election_, IsMaster()).WillRepeatedly(Return(false));
  EXPECT_EQ(util::error::PERMISSION_DENIED,
            RunOneCleanUpIteration(234).CanonicalCode());
}


TEST_F(EtcdConsistentStoreTest, TestCleansUpOnNewSTH) {
  PopulateForCleanupTests(5, 4, 100);

  // Be sure about our starting state of sequenced entries so we can compare
  // later on
  vector<EntryHandle<LoggedCertificate>> seq_entries;
  CHECK(store_->GetSequencedEntries(&seq_entries).ok());
  EXPECT_EQ(5, seq_entries.size());

  // Do the same for the unsequenced entries
  vector<EntryHandle<LoggedCertificate>> unseq_entries_pre;
  CHECK(store_->GetPendingEntries(&unseq_entries_pre).ok());
  // Prune out any "unsequenced" entries which have counterparts in the
  // "sequenced" set:
  auto it(unseq_entries_pre.begin());
  while (it != unseq_entries_pre.end()) {
    if (it->Entry().has_provisional_sequence_number()) {
      it = unseq_entries_pre.erase(it);
    } else {
      ++it;
    }
  }
  EXPECT_EQ(4, unseq_entries_pre.size());

  EXPECT_CALL(election_, IsMaster()).WillRepeatedly(Return(true));

  // Set ServingSTH to something which will cause entries 100, 101, and 102 to
  // be cleaned up:
  SignedTreeHead sth;
  sth.set_timestamp(345345);
  sth.set_tree_size(103);
  CHECK(store_->SetServingSTH(sth).ok());
  sleep(1);

  // Check that they were cleaned up:
  seq_entries.clear();
  CHECK(store_->GetSequencedEntries(&seq_entries).ok());
  // 103 & 104 remaining:
  EXPECT_EQ(2, seq_entries.size());
  EXPECT_EQ(103, seq_entries[0].Entry().sequence_number());
  EXPECT_EQ(104, seq_entries[1].Entry().sequence_number());

  // Now update ServingSTH so that all sequenced entries should be cleaned up:
  sth.set_timestamp(sth.timestamp() + 1);
  sth.set_tree_size(105);
  CHECK(store_->SetServingSTH(sth).ok());
  sleep(1);

  // Ensure they were:
  seq_entries.clear();
  CHECK(store_->GetSequencedEntries(&seq_entries).ok());
  EXPECT_EQ(0, seq_entries.size());

  // Check we've not touched the unseqenced entries:
  vector<EntryHandle<LoggedCertificate>> unseq_entries_post;
  CHECK(store_->GetPendingEntries(&unseq_entries_post).ok());
  EXPECT_EQ(unseq_entries_pre.size(), unseq_entries_post.size());
  for (int i = 0; i < unseq_entries_pre.size(); ++i) {
    EXPECT_EQ(unseq_entries_pre[i].Handle(), unseq_entries_post[i].Handle());
    EXPECT_EQ(unseq_entries_pre[i].Entry(), unseq_entries_post[i].Entry());
  }
}


}  // namespace cert_trans

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  ::testing::FLAGS_gtest_death_test_style = "threadsafe";
  return RUN_ALL_TESTS();
}
