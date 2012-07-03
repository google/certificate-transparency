#include <assert.h>
#include <vector>

#include "../include/types.h"
#include "../util/util.h"
#include "cert.h"
#include "log_entry.h"

// static
LogEntry *LogEntry::Deserialize(const bstring &record) {
  if (record.size() < 2)
    return NULL;
  size_t type = util::DeserializeUint(record.substr(0, 2));
  LogEntry *entry = NULL;
  switch(type) {
    case LogEntry::X509_CHAIN_ENTRY:
      entry = new X509ChainEntry();
      break;
    case LogEntry::PROTOCERT_CHAIN_ENTRY:
      entry = new ProtoCertChainEntry();
      break;
    case LogEntry::TEST_ENTRY:
      entry = new TestEntry();
      break;
    default:
      return NULL;
  }

  assert(entry != NULL);
  if (!entry->DeserializeImpl(record.substr(2))) {
    delete entry;
    entry = NULL;
  }
  return entry;
}

// Certs, chains and entries are serialized to max 2^24-1 bytes.
static const size_t kMaxSerializedLength = (1 << 24) - 1;
static const size_t kPrefixLength = 3;

// Append a length-prefixed string to the result.
static bool AppendVarLengthString(const bstring &var_length_string,
                                  bstring *result) {
  assert(result != NULL);
  assert(result->size() < kMaxSerializedLength);

  if (kMaxSerializedLength - result->size() < kPrefixLength)
    return false;
  result->append(util::SerializeUint(var_length_string.size(), kPrefixLength));

  if (kMaxSerializedLength - result->size() < var_length_string.size())
    return false;
  result->append(var_length_string);
  return true;
}

// Return the number of bytes read, or 0 on error.
static size_t ReadVarLengthString(const bstring &record,
                                  bstring *var_length_string) {
  assert(var_length_string != NULL);
  if (record.size() < kPrefixLength)
    return 0;
  size_t string_length =
      util::DeserializeUint(record.substr(0, kPrefixLength));
  if (record.size() - kPrefixLength < string_length)
    return 0;
  var_length_string->assign(record.substr(kPrefixLength, string_length));
  return kPrefixLength + string_length;
}

X509ChainEntry::X509ChainEntry(const CertChain &chain) {
  assert(chain.IsLoaded());
  for (size_t i = 0; i < chain.Length(); ++i)
    certificate_chain_.push_back(chain.CertAt(i)->DerEncoding());
}

bool X509ChainEntry::SerializeImpl(bstring *result) const {
  assert(result != NULL);
  if (certificate_chain_.empty() || certificate_chain_[0].empty())
    return false;

  bstring chain;
  for (size_t i = 0; i < certificate_chain_.size(); ++i) {
    if (!AppendVarLengthString(certificate_chain_[i], &chain))
      return false;
  }

  result->clear();
  if (!AppendVarLengthString(chain, result)) {
    result->clear();
    return false;
  }

  return true;
}

bool X509ChainEntry::DeserializeImpl(const bstring &record) {
  bstring chain;

  size_t bytes_read = ReadVarLengthString(record, &chain);
  if (bytes_read == 0 || bytes_read != record.size() || chain.empty())
    return false;

  size_t pos = 0;
  while (pos < chain.size()) {
    bstring cert_string;
    size_t read_bytes = ReadVarLengthString(chain.substr(pos), &cert_string);
    if (!read_bytes || cert_string.empty()) {
      certificate_chain_.clear();
      return false;
    }
    certificate_chain_.push_back(cert_string);
    pos += read_bytes;
  }
  return true;
}

// Caller is responsible for ensuring the protocert chain is well-formed.
ProtoCertChainEntry::ProtoCertChainEntry(const ProtoCertChain &chain) {
  assert(chain.IsLoaded());
  assert(chain.IsWellFormed());

  const Cert *protocert = chain.ProtoCert();
  assert(protocert != NULL && protocert->IsLoaded());

  // Get a local copy of the protocert.
  Cert *tbs = protocert->Clone();
  assert(tbs != NULL && tbs->IsLoaded());

 // Remove the poison extension and the signature.
  tbs->DeleteExtension(Cert::kPoisonExtensionOID);
  tbs->DeleteSignature();

  // Fix the issuer.
  const Cert *ca_protocert = chain.CaProtoCert();
  assert(ca_protocert != NULL && ca_protocert->IsLoaded());
  tbs->CopyIssuerFrom(*ca_protocert);

  tbs_ = tbs->DerEncoding();
  delete tbs;

  ca_protocert_ = ca_protocert->DerEncoding();
  protocert_ = protocert->DerEncoding();

 for (size_t i = 0; i < chain.IntermediateLength(); ++i)
  intermediates_.push_back(chain.IntermediateAt(i)->DerEncoding());
}

// Load the tbs_ and the intermediates from the chain.
// This initializes just enough of the protocert chain to compute
// the signed part.
ProtoCertChainEntry::ProtoCertChainEntry(const CertChain &chain) {
  assert(chain.IsLoaded());

  const Cert *leaf = chain.LeafCert();
  assert(leaf != NULL && leaf->IsLoaded());

  Cert *tbs = leaf->Clone();

  // Delete the signature and the embedded proof.
  tbs->DeleteSignature();
  tbs->DeleteExtension(Cert::kEmbeddedProofExtensionOID);

  tbs_ = tbs->DerEncoding();
  delete tbs;

  for (size_t i = 1; i < chain.Length(); ++i)
    intermediates_.push_back(chain.CertAt(i)->DerEncoding());
}

bool ProtoCertChainEntry::SerializeSignedImpl(bstring *result) const {
  assert(result != NULL);

  bstring local;
  if (tbs_.empty() || !AppendVarLengthString(tbs_, &local))
    return false;

  bstring chain;
  for (size_t i = 0; i < intermediates_.size(); ++i) {
    if (!AppendVarLengthString(intermediates_[i], &chain))
      return false;
  }

  if (!AppendVarLengthString(chain, &local))
    return false;

  result->assign(local);
  return true;
}

bool ProtoCertChainEntry::SerializeImpl(bstring *result) const {
  bstring signed_part;
  if (!SerializeSignedImpl(&signed_part))
    return false;
  if (protocert_.empty() || ca_protocert_.empty())
    return false;

  if (!AppendVarLengthString(protocert_, &signed_part) ||
      !AppendVarLengthString(ca_protocert_, &signed_part))
    return false;

  result->assign(signed_part);
  return true;
}

bool ProtoCertChainEntry::DeserializeImpl(const bstring &record) {
  bstring tbs;
  size_t bytes_read = ReadVarLengthString(record, &tbs);
  if (!bytes_read || tbs.empty())
    return false;

  size_t pos = bytes_read;

  bstring chain;
  bytes_read = ReadVarLengthString(record.substr(pos), &chain);
  // Chain can have 0 length, so we don't check for chain.empty()
  if (!bytes_read)
    return false;
  pos += bytes_read;

  size_t chain_pos = 0;
  std::vector<bstring> intermediates;
  while (chain_pos < chain.size()) {
    bstring cert_string;
    bytes_read = ReadVarLengthString(chain.substr(chain_pos),
                                     &cert_string);
    if (!bytes_read || cert_string.empty())
      return false;

    intermediates.push_back(cert_string);
    chain_pos += bytes_read;
  }

  bstring protocert;
  bytes_read = ReadVarLengthString(record.substr(pos), &protocert);
  if (!bytes_read || protocert.empty())
    return false;
  pos += bytes_read;

  bstring ca_protocert;
  bytes_read = ReadVarLengthString(record.substr(pos), &ca_protocert);
  if (!bytes_read || ca_protocert.empty())
    return false;
  pos += bytes_read;

  // Check that we have reached the end.
  assert(pos == record.size());

  // All good, write members.
  tbs_ = tbs;
  intermediates_ = intermediates;
  protocert_ = protocert;
  ca_protocert_ = ca_protocert;
  return true;
}
