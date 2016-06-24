#include "log/logged_entry.h"

#include "proto/cert_serializer.h"
#include "proto/serializer.h"
#include "util/util.h"

using cert_trans::serialization::SerializeResult;
using ct::CertInfo;
using ct::LogEntry;
using ct::PreCert;
using ct::SignedCertificateTimestamp;
using std::string;
using util::RandomString;

namespace cert_trans {


string LoggedEntry::Hash() const {
  return Sha256Hasher::Sha256Digest(Serializer::LeafData(entry()));
}


bool LoggedEntry::SerializeForLeaf(string* dst) const {
  return Serializer::SerializeSCTMerkleTreeLeaf(sct(), entry(), dst) ==
         SerializeResult::OK;
}


bool LoggedEntry::SerializeExtraData(string* dst) const {
  switch (entry().type()) {
    case ct::X509_ENTRY:
      return SerializeX509Chain(entry().x509_entry(), dst) ==
             SerializeResult::OK;
    case ct::PRECERT_ENTRY:
      return SerializePrecertChainEntry(entry().precert_entry(), dst) ==
             SerializeResult::OK;
    case ct::PRECERT_ENTRY_V2:
      // TODO(mhs): V2 implementation needs to be provided.
      LOG(FATAL) << "CT V2 not yet implemented";
      break;
    case ct::X_JSON_ENTRY:
      dst->clear();
      return true;
    case ct::UNKNOWN_ENTRY_TYPE:
      // We'll handle this below, along with any unknown unknown types too.
      break;
  }
  LOG(FATAL) << "Unknown entry type " << entry().type();
}


bool LoggedEntry::CopyFromClientLogEntry(const AsyncLogClient::Entry& entry) {
  if (entry.leaf.timestamped_entry().entry_type() != ct::X509_ENTRY &&
      entry.leaf.timestamped_entry().entry_type() != ct::PRECERT_ENTRY &&
      entry.leaf.timestamped_entry().entry_type() != ct::X_JSON_ENTRY) {
    LOG(INFO) << "unsupported entry_type: "
              << entry.leaf.timestamped_entry().entry_type();
    return false;
  }

  Clear();

  ct::SignedCertificateTimestamp* const sct(mutable_contents()->mutable_sct());
  sct->set_version(ct::V1);
  sct->set_timestamp(entry.leaf.timestamped_entry().timestamp());
  sct->set_extensions(entry.leaf.timestamped_entry().extensions());

  // It may look like you should just be able to copy entry.entry over
  // contents.entry, but entry.entry is incomplete (when the same
  // information is available in entry.leaf, it will be missing from
  // entry.entry). So we still need to fill in some missing bits...
  LogEntry* const log_entry(mutable_contents()->mutable_entry());
  log_entry->CopyFrom(entry.entry);
  log_entry->set_type(entry.leaf.timestamped_entry().entry_type());
  switch (contents().entry().type()) {
    case ct::X509_ENTRY: {
      log_entry->mutable_x509_entry()->set_leaf_certificate(
          entry.leaf.timestamped_entry().signed_entry().x509());
      break;
    }

    case ct::PRECERT_ENTRY: {
      PreCert* const precert(
          log_entry->mutable_precert_entry()->mutable_pre_cert());
      precert->set_issuer_key_hash(entry.leaf.timestamped_entry()
                                       .signed_entry()
                                       .precert()
                                       .issuer_key_hash());
      precert->set_tbs_certificate(entry.leaf.timestamped_entry()
                                       .signed_entry()
                                       .precert()
                                       .tbs_certificate());
      break;
    }

    case ct::X_JSON_ENTRY: {
      log_entry->mutable_x_json_entry()->set_json(
          entry.leaf.timestamped_entry().signed_entry().json());
      break;
    }

    case ct::PRECERT_ENTRY_V2: {
      // TODO(mhs): V2 implementation here + other changes above
      LOG(FATAL) << "CT V2 not yet implemented";
      break;
    }

    default:
      LOG(FATAL) << "unknown entry type";
  }

  return true;
}


void LoggedEntry::RandomForTest() {
  const char kKeyID[] =
      "b69d879e3f2c4402556dcda2f6b2e02ff6b6df4789c53000e14f4b125ae847aa";

  mutable_sct()->set_version(ct::V1);
  mutable_sct()->mutable_id()->set_key_id(util::BinaryString(kKeyID));
  mutable_sct()->set_timestamp(util::TimeInMilliseconds());
  mutable_sct()->clear_extensions();

  const int random_bits(rand());
  ct::LogEntryType type(random_bits & 1 ? ct::X509_ENTRY : ct::PRECERT_ENTRY);
  ct::LogEntry* const entry(mutable_entry());

  entry->set_type(type);
  entry->clear_x509_entry();
  entry->clear_precert_entry();

  if (type == ct::X509_ENTRY) {
    entry->mutable_x509_entry()->set_leaf_certificate(RandomString(512, 1024));
    if (random_bits & 2) {
      entry->mutable_x509_entry()->add_certificate_chain(
          RandomString(512, 1024));

      if (random_bits & 4) {
        entry->mutable_x509_entry()->add_certificate_chain(
            RandomString(512, 1024));
      }
    }
  } else {
    entry->mutable_precert_entry()->mutable_pre_cert()->set_issuer_key_hash(
        RandomString(32, 32));
    entry->mutable_precert_entry()->mutable_pre_cert()->set_tbs_certificate(
        RandomString(512, 1024));
    entry->mutable_precert_entry()->set_pre_certificate(
        RandomString(512, 1024));
    if (random_bits & 2) {
      entry->mutable_precert_entry()->add_precertificate_chain(
          RandomString(512, 1024));

      if (random_bits & 4) {
        entry->mutable_precert_entry()->add_precertificate_chain(
            RandomString(512, 1024));
      }
    }
  }
}


}  // namespace cert_trans
