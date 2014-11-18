#include "log/etcd_consistent_store-inl.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>

#include "log/logged_certificate.h"
#include "proto/ct.pb.h"
#include "util/mock_sync_etcd.h"
#include "util/testing.h"

namespace cert_trans {


using std::vector;
using std::pair;
using std::string;
using testing::_;
using testing::Return;
using testing::SetArgumentPointee;
using util::Status;


const char kRoot[] = "/root";
const char kNodeId[] = "node_id";
const int kTimestamp = 9000;


class EtcdConsistentStoreTest : public ::testing::Test {
 protected:
  void SetUp() override {
    store_.reset(
        new EtcdConsistentStore<LoggedCertificate>(&client_, kRoot, kNodeId));
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

  template <class T>
  string Serialize(const T& t) {
    string flat;
    t.SerializeToString(&flat);
    return flat;
  }

  template <class T>
  EtcdClient::Node NodeFor(const int index, const std::string& key,
                           const T& t) {
    return EtcdClient::Node(index, key, Serialize(t));
  }

  MockSyncEtcdClient client_;
  std::unique_ptr<EtcdConsistentStore<LoggedCertificate>> store_;
};


typedef class EtcdConsistentStoreTest EtcdConsistentStoreDeathTest;

TEST_F(EtcdConsistentStoreDeathTest, TestNextAvailableSequenceNumber) {
  EXPECT_DEATH(store_->NextAvailableSequenceNumber(), "Not Implemented");
}


TEST_F(EtcdConsistentStoreTest, TestSetServingSTH) {
  ct::SignedTreeHead sth;
  EXPECT_EQ(util::error::UNIMPLEMENTED,
            store_->SetServingSTH(sth).CanonicalCode());
}


TEST_F(EtcdConsistentStoreTest, TestAddPendingEntryWorks) {
  LoggedCertificate cert(DefaultCert());
  EXPECT_CALL(client_, Create(string(kRoot) + "/unsequenced/" +
                                  util::ToBase64(cert.Hash()),
                              _, _)).WillOnce(Return(util::Status::OK));
  util::Status status(store_->AddPendingEntry(&cert));
  EXPECT_TRUE(status.ok()) << status;
}


TEST_F(EtcdConsistentStoreTest,
       TestAddPendingEntryForExistingEntryReturnsSct) {
  LoggedCertificate cert(DefaultCert());
  LoggedCertificate other_cert(DefaultCert());
  other_cert.mutable_sct()->set_timestamp(55555);

  const string kKey(util::ToBase64(cert.Hash()));
  const string kPath(string(kRoot) + "/unsequenced/" + kKey);
  EXPECT_CALL(client_, Create(kPath, _, _))
      .WillOnce(Return(util::Status(util::error::FAILED_PRECONDITION, "")));
  EXPECT_CALL(client_, Get(kPath, _))
      .WillOnce(DoAll(SetArgumentPointee<1>(NodeFor(0, kPath, other_cert)),
                      Return(util::Status::OK)));
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
  EXPECT_DEATH({
                 EXPECT_CALL(client_, Create(kPath, _, _))
                     .WillOnce(Return(
                         util::Status(util::error::FAILED_PRECONDITION, "")));
                 EXPECT_CALL(client_, Get(kPath, _))
                     .WillOnce(DoAll(SetArgumentPointee<1>(
                                         NodeFor(0, kPath, other_cert)),
                                     Return(util::Status::OK)));
                 store_->AddPendingEntry(&cert);
               },
               "preexisting_entry.*==.*entry.*");
}


TEST_F(EtcdConsistentStoreDeathTest,
       TestAddPendingEntryDoesNotAcceptSequencedEntry) {
  LoggedCertificate cert(DefaultCert());
  cert.set_sequence_number(76);
  EXPECT_DEATH({
                 EXPECT_CALL(client_, Create(string(kRoot) + "/unsequenced/" +
                                                 util::ToBase64(cert.Hash()),
                                             _, _))
                     .WillOnce(Return(util::Status::OK));
                 store_->AddPendingEntry(&cert);
               },
               "!entry\\->has_sequence_number");
}


TEST_F(EtcdConsistentStoreTest, TestGetPendingEntryForHash) {
  const LoggedCertificate one(MakeCert(123, "one"));
  const string kPath(string(kRoot) + "/unsequenced/" +
                     util::ToBase64(one.Hash()));
  EXPECT_CALL(client_, Get(kPath, _))
      .WillOnce(DoAll(SetArgumentPointee<1>(NodeFor(17, kPath, one)),
                      Return(util::Status::OK)));

  EntryHandle<LoggedCertificate> handle;
  util::Status status(store_->GetPendingEntryForHash(one.Hash(), &handle));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(one, handle.Entry());
  EXPECT_EQ(17, handle.Handle());
}


TEST_F(EtcdConsistentStoreTest, TestGetPendingEntryForNonExistantHash) {
  const string kPath(string(kRoot) + "/unsequenced/" + util::ToBase64("Nah"));
  EXPECT_CALL(client_, Get(kPath, _))
      .WillOnce(Return(util::Status(util::error::NOT_FOUND, "")));

  EntryHandle<LoggedCertificate> handle;
  util::Status status(store_->GetPendingEntryForHash("Nah", &handle));
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(EtcdConsistentStoreTest, TestGetPendingEntries) {
  const string kPath(string(kRoot) + "/unsequenced/");
  const LoggedCertificate one(MakeCert(123, "one"));
  const LoggedCertificate two(MakeCert(456, "two"));
  const vector<EtcdClient::Node> nodes{NodeFor(1, "/unsequenced/one", one),
                                       NodeFor(6, "/unsequenced/two", two)};
  EXPECT_CALL(client_, GetAll(kPath, _))
      .WillOnce(DoAll(SetArgumentPointee<1>(nodes), Return(util::Status::OK)));

  vector<EntryHandle<LoggedCertificate>> entries;
  util::Status status(store_->GetPendingEntries(&entries));
  EXPECT_TRUE(status.ok()) << status;
}


TEST_F(EtcdConsistentStoreTest, TestGetPendingEntriesFails) {
  EXPECT_CALL(client_, GetAll(_, _))
      .WillOnce(Return(util::Status(util::error::UNKNOWN, "")));

  vector<EntryHandle<LoggedCertificate>> entries;
  util::Status status(store_->GetPendingEntries(&entries));

  EXPECT_EQ(util::error::UNKNOWN, status.CanonicalCode()) << status;
}


TEST_F(EtcdConsistentStoreDeathTest,
       TestGetPendingEntriesBarfsWithSequencedEntry) {
  const string kPath(string(kRoot) + "/unsequenced/");
  LoggedCertificate one(MakeSequencedCert(123, "one", 666));
  const vector<EtcdClient::Node> nodes{NodeFor(1, "/unsequenced/one", one)};
  EXPECT_DEATH({
                 EXPECT_CALL(client_, GetAll(kPath, _))
                     .WillOnce(DoAll(SetArgumentPointee<1>(nodes),
                                     Return(util::Status::OK)));
                 vector<EntryHandle<LoggedCertificate>> entries;
                 util::Status status(store_->GetPendingEntries(&entries));
               },
               "has_sequence_number");
}


TEST_F(EtcdConsistentStoreTest, TestGetSequencedEntries) {
  const string kPath(string(kRoot) + "/sequenced/");
  const LoggedCertificate one(MakeSequencedCert(123, "one", 1));
  const LoggedCertificate two(MakeSequencedCert(456, "two", 2));
  const vector<EtcdClient::Node> nodes{NodeFor(1, "/sequenced/1", one),
                                       NodeFor(6, "/sequenced/6", two)};
  EXPECT_CALL(client_, GetAll(kPath, _))
      .WillOnce(DoAll(SetArgumentPointee<1>(nodes), Return(util::Status::OK)));

  vector<EntryHandle<LoggedCertificate>> entries;
  util::Status status(store_->GetSequencedEntries(&entries));
}


TEST_F(EtcdConsistentStoreTest, TestGetSequencedEntriesFails) {
  EXPECT_CALL(client_, GetAll(_, _))
      .WillOnce(Return(util::Status(util::error::UNKNOWN, "")));

  vector<EntryHandle<LoggedCertificate>> entries;
  util::Status status(store_->GetSequencedEntries(&entries));

  EXPECT_EQ(util::error::UNKNOWN, status.CanonicalCode()) << status;
}


TEST_F(EtcdConsistentStoreDeathTest,
       TestGetSequencedEntriesBarfsWitUnsSequencedEntry) {
  const string kPath(string(kRoot) + "/sequenced/");
  LoggedCertificate one(MakeCert(123, "one"));
  const vector<EtcdClient::Node> nodes{NodeFor(1, "/sequenced/1", one)};
  EXPECT_DEATH({
                 EXPECT_CALL(client_, GetAll(kPath, _))
                     .WillOnce(DoAll(SetArgumentPointee<1>(nodes),
                                     Return(util::Status::OK)));
                 vector<EntryHandle<LoggedCertificate>> entries;
                 util::Status status(store_->GetSequencedEntries(&entries));
               },
               "has_sequence_number");
}


TEST_F(EtcdConsistentStoreTest, TestAssignSequenceNumber) {
  const int kDefaultHandle(23);
  EntryHandle<LoggedCertificate> entry(
      HandleForCert(DefaultCert(), kDefaultHandle));

  const string kUnsequencedPath(string(kRoot) + "/unsequenced/" +
                                util::ToBase64(entry.Entry().Hash()));
  const string kSequencedPath(string(kRoot) + "/sequenced/1");
  const int kSeq(1);


  LoggedCertificate entry_with_provisional(entry.Entry());
  entry_with_provisional.set_provisional_sequence_number(kSeq);
  EXPECT_CALL(client_,
              Update(kUnsequencedPath, Serialize(entry_with_provisional),
                     kDefaultHandle, _)).WillOnce(Return(util::Status::OK));

  LoggedCertificate entry_with_seq(entry.Entry());
  entry_with_seq.set_sequence_number(kSeq);
  EXPECT_CALL(client_, Create(kSequencedPath, Serialize(entry_with_seq), _))
      .WillOnce(Return(util::Status::OK));


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
  state.set_node_id("me");
  state.set_contiguous_tree_size(2342);

  EXPECT_CALL(client_, ForceSet(kPath, Serialize(state), _))
      .WillOnce(Return(util::Status::OK));

  util::Status status(store_->SetClusterNodeState(state));
  EXPECT_TRUE(status.ok()) << status;
}


TEST_F(EtcdConsistentStoreTest, TestSetClusterNodeStateFails) {
  const string kPath(string(kRoot) + "/nodes/" + kNodeId);

  ct::ClusterNodeState state;
  state.set_node_id("me");
  state.set_contiguous_tree_size(2342);

  EXPECT_CALL(client_, ForceSet(kPath, Serialize(state), _))
      .WillOnce(Return(util::Status(util::error::UNKNOWN, "?")));

  util::Status status(store_->SetClusterNodeState(state));
  EXPECT_EQ(util::error::UNKNOWN, status.CanonicalCode()) << status;
}


}  // namespace cert_trans

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
