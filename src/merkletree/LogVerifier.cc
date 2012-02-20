#include <string>

#include <assert.h>

#include <openssl/evp.h>

#include "LogRecord.h"
#include "LogVerifier.h"
#include "MerkleVerifier.h"
#include "SerialHasher.h"

LogVerifier::LogVerifier(EVP_PKEY *pkey) : pkey_(pkey),
                                           verifier_(new Sha256Hasher()) {
  assert(pkey_ != NULL && pkey_->type == EVP_PKEY_EC);
}

LogVerifier::~LogVerifier() {
  EVP_PKEY_free(pkey_);
}

bool LogVerifier::VerifyLogSegmentAuditProof(const AuditProof &audit_proof,
                                             const std::string &leaf) {
  assert(audit_proof.tree_type == SegmentData::LOG_SEGMENT_TREE);
  SegmentData data;
  data.sequence_number = audit_proof.sequence_number;
  data.segment_size = audit_proof.tree_size;
  std::string root = verifier_.RootFromPath(audit_proof.leaf_index + 1,
                                            audit_proof.tree_size,
                                            audit_proof.audit_path, leaf);
  if (root.empty())
    return false;
  assert(root.size() == 32);
  data.segment_root = root;
  data.segment_sig = audit_proof.signature;
  return VerifyLogSegmentSignature(data);
}

bool LogVerifier::VerifyLogSegmentSignature(const SegmentData &data) {
  if (data.segment_sig.hash_algo != DigitallySigned::SHA256 ||
      data.segment_sig.sig_algo != DigitallySigned::ECDSA)
    return false;
  std::string in = data.SerializeLogSegmentTreeData();
  return VerifySignature(in, data.segment_sig.signature);
}

bool LogVerifier::VerifySegmentInfoSignature(const SegmentData &data) {
  if (data.segment_info_sig.hash_algo != DigitallySigned::SHA256 ||
      data.segment_info_sig.sig_algo != DigitallySigned::ECDSA)
    return false;
  std::string in = data.SerializeSegmentInfoTreeData();
  return VerifySignature(in, data.segment_info_sig.signature);
}

bool LogVerifier::VerifySignature(const std::string &data,
                                  const std::string &signature) {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  assert(EVP_VerifyInit(&ctx, EVP_sha256()) == 1);
  assert(EVP_VerifyUpdate(&ctx, data.data(), data.size()) == 1);
  bool ret =
    (EVP_VerifyFinal(&ctx,
		     reinterpret_cast<const unsigned char*>(signature.data()),
		     signature.size(), pkey_) == 1);
  EVP_MD_CTX_cleanup(&ctx);
  return ret;
}
