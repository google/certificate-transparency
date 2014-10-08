/* -*- mode: c++; indent-tabs-mode: nil -*- */

#ifndef LOGGED_CERTIFICATE_H
#define LOGGED_CERTIFICATE_H

#include "merkletree/serial_hasher.h"
#include "proto/ct.pb.h"
#include "proto/serializer.h"
#include "util/util.h"

namespace cert_trans {

class LoggedCertificate : public ct::LoggedCertificatePB {
 public:
  std::string Hash() const {
    return Sha256Hasher::Sha256Digest(Serializer::LeafCertificate(entry()));
  }

  uint64_t timestamp() const {
    return sct().timestamp();
  }

  const ct::SignedCertificateTimestamp& sct() const {
    return contents().sct();
  }

  ct::SignedCertificateTimestamp* mutable_sct() {
    return mutable_contents()->mutable_sct();
  }

  const ct::LogEntry& entry() const {
    return contents().entry();
  }

  ct::LogEntry* mutable_entry() {
    return mutable_contents()->mutable_entry();
  }

  bool SerializeForDatabase(std::string* dst) const {
    return contents().SerializeToString(dst);
  }

  bool ParseFromDatabase(const std::string& src) {
    return mutable_contents()->ParseFromString(src);
  }

  bool SerializeForLeaf(std::string* dst) const {
    return Serializer::SerializeSCTMerkleTreeLeaf(sct(), entry(), dst) ==
           Serializer::OK;
  }

  bool SerializeExtraData(std::string* dst) const {
    if (entry().type() == ct::X509_ENTRY)
      return Serializer::SerializeX509Chain(entry().x509_entry(), dst) ==
             Serializer::OK;
    else
      return Serializer::SerializePrecertChainEntry(entry().precert_entry(),
                                                    dst) == Serializer::OK;
  }

  // FIXME(benl): unify with TestSigner?
  void RandomForTest() {
    const char kKeyID[] =
        "b69d879e3f2c4402556dcda2f6b2e02ff6b6df4789c53000e14f4b125ae847aa";

    mutable_sct()->set_version(ct::V1);
    mutable_sct()->mutable_id()->set_key_id(util::BinaryString(kKeyID));
    mutable_sct()->set_timestamp(util::TimeInMilliseconds());
    mutable_sct()->clear_extensions();

    int random_bits = rand();
    ct::LogEntryType type =
        random_bits & 1 ? ct::X509_ENTRY : ct::PRECERT_ENTRY;

    ct::LogEntry* entry = mutable_entry();

    entry->set_type(type);
    entry->clear_x509_entry();
    entry->clear_precert_entry();

    if (type == ct::X509_ENTRY) {
      entry->mutable_x509_entry()->set_leaf_certificate(
          util::RandomString(512, 1024));
      if (random_bits & 2) {
        entry->mutable_x509_entry()->add_certificate_chain(
            util::RandomString(512, 1024));

        if (random_bits & 4) {
          entry->mutable_x509_entry()->add_certificate_chain(
              util::RandomString(512, 1024));
        }
      }
    } else {
      entry->mutable_precert_entry()->mutable_pre_cert()->set_issuer_key_hash(
          util::RandomString(32, 32));
      entry->mutable_precert_entry()->mutable_pre_cert()->set_tbs_certificate(
          util::RandomString(512, 1024));
      entry->mutable_precert_entry()->set_pre_certificate(
          util::RandomString(512, 1024));
      if (random_bits & 2) {
        entry->mutable_precert_entry()->add_precertificate_chain(
            util::RandomString(512, 1024));

        if (random_bits & 4) {
          entry->mutable_precert_entry()->add_precertificate_chain(
              util::RandomString(512, 1024));
        }
      }
    }
  }
};

}  // namespace cert_trans

#endif
