#include "log/fake_consistent_store-inl.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <map>
#include <memory>
#include <string>

#include "log/logged_certificate.h"
#include "proto/ct.pb.h"
#include "util/testing.h"

namespace cert_trans {


using std::vector;
using std::pair;
using std::string;
using std::to_string;
using testing::_;
using testing::Contains;
using testing::Return;
using testing::SetArgumentPointee;
using util::Status;


const char kNodeId[] = "node-id";
const int kTimestamp = 123;


class FakeConsistentStoreTest : public ::testing::Test {
 protected:
  void SetUp() override {
    store_.reset(new FakeConsistentStore<LoggedCertificate>(kNodeId));
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

  string Serialize(const LoggedCertificate& cert) {
    string flat;
    cert.SerializeToString(&flat);
    return flat;
  }

  const ct::SignedTreeHead& GetServingSTH() {
    return *store_->tree_head_;
  }

  const EntryHandle<LoggedCertificate>& GetPendingEntry(const string& key) {
    return store_->pending_entries_[key];
  }

  const EntryHandle<LoggedCertificate>& GetSequencedEntry(int seq) {
    return store_->sequenced_entries_[to_string(seq)];
  }

  void SetSequencedEntry(int seq, const LoggedCertificate& e, int version) {
    store_->sequenced_entries_.emplace(
        std::to_string(seq), EntryHandle<LoggedCertificate>(e, version));
  }

  const ct::ClusterNodeState& GetClusterNodeState(const string& key) {
    return store_->node_states_[key];
  }


  std::unique_ptr<FakeConsistentStore<LoggedCertificate>> store_;
};


TEST_F(FakeConsistentStoreTest, TestNextAvailableSequenceNumber) {
  EXPECT_EQ(0, store_->NextAvailableSequenceNumber().ValueOrDie());
}


TEST_F(FakeConsistentStoreTest, TestSetServingSTH) {
  ct::SignedTreeHead sth;
  sth.set_timestamp(234);
  util::Status status(store_->SetServingSTH(sth));
  EXPECT_EQ(true, status.ok()) << status;
  EXPECT_EQ(sth.DebugString(), GetServingSTH().DebugString());
}


TEST_F(FakeConsistentStoreTest, TestAddPendingEntryWorks) {
  LoggedCertificate cert(DefaultCert());
  util::Status status(store_->AddPendingEntry(&cert));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(cert, GetPendingEntry(util::ToBase64(cert.Hash())).Entry());
}


TEST_F(FakeConsistentStoreTest,
       TestAddPendingEntryForExistingEntryReturnsSct) {
  LoggedCertificate cert(DefaultCert());
  LoggedCertificate other_cert(DefaultCert());
  other_cert.mutable_sct()->set_timestamp(55555);

  util::Status status(store_->AddPendingEntry(&cert));
  EXPECT_TRUE(status.ok()) << status;
  status = store_->AddPendingEntry(&other_cert);
  EXPECT_EQ(util::error::ALREADY_EXISTS, status.CanonicalCode()) << status;
  EXPECT_EQ(other_cert.timestamp(), cert.timestamp());
}


TEST_F(FakeConsistentStoreTest, TestGetPendingEntryForHash) {
  LoggedCertificate one(MakeCert(123, "one"));
  EXPECT_TRUE(store_->AddPendingEntry(&one).ok());

  EntryHandle<LoggedCertificate> entry;
  util::Status status(store_->GetPendingEntryForHash(one.Hash(), &entry));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(one, entry.Entry());
}


TEST_F(FakeConsistentStoreTest, TestGetPendingEntryForNonExistentHash) {
  EntryHandle<LoggedCertificate> entry;
  util::Status status(store_->GetPendingEntryForHash("Nah", &entry));
  EXPECT_EQ(util::error::NOT_FOUND, status.CanonicalCode()) << status;
}


TEST_F(FakeConsistentStoreTest, TestGetPendingEntries) {
  LoggedCertificate one(MakeCert(123, "one"));
  LoggedCertificate two(MakeCert(456, "two"));
  EXPECT_TRUE(store_->AddPendingEntry(&one).ok());
  EXPECT_TRUE(store_->AddPendingEntry(&two).ok());

  vector<EntryHandle<LoggedCertificate>> entries;
  util::Status status(store_->GetPendingEntries(&entries));
  EXPECT_TRUE(status.ok()) << status;

  EXPECT_EQ(2, entries.size());
  vector<LoggedCertificate> certs;
  for (auto& e : entries) {
    certs.push_back(e.Entry());
  }
  EXPECT_THAT(certs, Contains(one));
  EXPECT_THAT(certs, Contains(two));
}


TEST_F(FakeConsistentStoreTest, TestGetSequencedEntries) {
  LoggedCertificate one(MakeSequencedCert(123, "one", 1));
  LoggedCertificate two(MakeSequencedCert(456, "two", 2));
  SetSequencedEntry(1, one, 0);
  SetSequencedEntry(2, two, 0);

  vector<EntryHandle<LoggedCertificate>> entries;
  util::Status status(store_->GetSequencedEntries(&entries));

  vector<LoggedCertificate> certs;
  for (auto& e : entries) {
    certs.push_back(e.Entry());
  }
  EXPECT_THAT(certs, Contains(one));
  EXPECT_THAT(certs, Contains(two));
}


TEST_F(FakeConsistentStoreTest, TestAssignSequenceNumber) {
  LoggedCertificate one(MakeCert(123, "one"));
  LoggedCertificate two(MakeCert(456, "two"));

  EXPECT_TRUE(store_->AddPendingEntry(&one).ok());
  EXPECT_TRUE(store_->AddPendingEntry(&two).ok());

  vector<EntryHandle<LoggedCertificate>> entries;
  util::Status status(store_->GetPendingEntries(&entries));
  EXPECT_TRUE(status.ok()) << status;

  int i(0);
  for (auto& e : entries) {
    EXPECT_EQ(i, store_->NextAvailableSequenceNumber().ValueOrDie());
    status = store_->AssignSequenceNumber(i++, &e);
    EXPECT_TRUE(status.ok()) << status;
    EXPECT_EQ(i, store_->NextAvailableSequenceNumber().ValueOrDie());
  }

  EXPECT_EQ(entries[0].Entry(), GetSequencedEntry(0).Entry());
  EXPECT_EQ(entries[1].Entry(), GetSequencedEntry(1).Entry());
}


TEST_F(FakeConsistentStoreTest, TestSetClusterNodeState) {
  ct::ClusterNodeState state;
  util::Status status(store_->SetClusterNodeState(state));
  EXPECT_TRUE(status.ok()) << status;
  EXPECT_EQ(state.DebugString(), GetClusterNodeState(kNodeId).DebugString());
}


}  // namespace cert_trans

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
