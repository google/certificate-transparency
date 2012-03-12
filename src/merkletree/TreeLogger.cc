#include <string>
#include <vector>

#include <assert.h>
#include <stddef.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10000000
# error "Need OpenSSL >= 1.0.0"
#endif

#include "LogDB.h"
#include "LogRecord.h"
#include "MerkleTree.h"
#include "SerialHasher.h"
#include "TreeLogger.h"

TreeLogger::TreeLogger(LogDB *db, EVP_PKEY *pkey)
  : db_(db), pkey_(pkey), segment_infos_(new Sha256Hasher()) {
  // For now, the signature and hash algorithms are hard-coded.
  assert(pkey_ != NULL && pkey_->type == EVP_PKEY_EC);
  // Start the first segment.
  logsegments_.push_back(new MerkleTree(new Sha256Hasher()));
}

TreeLogger::~TreeLogger() {
  delete db_;
  EVP_PKEY_free(pkey_);
  for (std::vector<MerkleTree*>::iterator it = logsegments_.begin();
       it < logsegments_.end(); ++it)
    delete *it;
}

// TODO: include log entry type.
LogDB::Status TreeLogger::QueueEntry(const std::string &data,
                                     std::string *key) {
  // First check whether the entry already exists.
  std::string hash = logsegments_.back()->LeafHash(data);
  assert(!hash.empty());
  LogDB::Status status = db_->WriteEntry(hash, data);

  switch(status) {
  case(LogDB::LOGGED):
  case(LogDB::PENDING):
    break;
  case(LogDB::NEW):
    // Work the data into the tree.
    logsegments_.back()->AddLeaf(data);
    break;
  default:
    assert(false);
  }

  if (key != NULL)
    key->assign(hash);
  return status;
}

/*
LogDB::Status TreeLogger::EntryInfo(size_t index,
                                    LogDB::Lookup type,
                                    std::string *result) {
  return db_->LookupEntry(index, type, result);
}
*/

LogDB::Status TreeLogger::EntryInfo(size_t segment, size_t index,
                                    LogDB::Lookup type,
                                    std::string *result) {
  return db_->LookupEntry(segment, index, type, result);
}

LogDB::Status TreeLogger::EntryInfo(const std::string &key,
                                    LogDB::Lookup type,
                                    std::string *result) {
  return db_->LookupEntry(key, type, result);
}

LogDB::Status TreeLogger::SegmentInfo(size_t index,
                                      std::string *result) {
  return db_->LookupSegmentInfo(index, result);
}

LogDB::Status TreeLogger::EntryAuditProof(const std::string &key,
                                          AuditProof *proof) {
  size_t segment, index;
  LogDB::Status status = db_->EntryLocation(key, &segment, &index);
  if (status != LogDB::LOGGED)
    return status;
  assert(proof != NULL);
  proof->tree_type = SegmentData::LOG_SEGMENT_TREE;
  proof->sequence_number = segment;
  proof->tree_size = logsegments_[segment]->LeafCount();
  assert(logsegments_[segment]->LeafHash(index + 1) == key);
  proof->leaf_index = index;
  std::string segment_info;
  assert(SegmentInfo(segment, &segment_info) == LogDB::LOGGED);
  SegmentData data;
  assert(data.DeserializeSegmentInfo(segment_info));
  proof->signature = data.segment_sig;
  proof->audit_path = logsegments_[segment]->PathToCurrentRoot(index + 1);
  return status;
}

void TreeLogger::LogSegment() {
  SegmentData data;
  data.segment_size = PendingLogSize();
  assert(data.segment_size == logsegments_.back()->LeafCount());

  data.sequence_number = SegmentCount();
  assert(data.sequence_number + 1 == logsegments_.size());

  data.segment_root = logsegments_.back()->CurrentRoot();
  assert(!data.segment_root.empty());

  std::string treedata = data.SerializeLogSegmentTreeData();
  data.segment_sig.hash_algo = DigitallySigned::SHA256;
  data.segment_sig.sig_algo = DigitallySigned::ECDSA;
  data.segment_sig.signature = Sign(treedata);

  assert(!data.segment_sig.signature.empty());

  // Append the signature to the segment info tree.
  segment_infos_.AddLeaf(data.segment_sig.signature);
  assert(segment_infos_.LeafCount() == data.sequence_number + 1);

  data.segment_info_root = segment_infos_.CurrentRoot();
  assert(!data.segment_info_root.empty());

  treedata = data.SerializeSegmentInfoTreeData();
  data.segment_info_sig.hash_algo = DigitallySigned::SHA256;
  data.segment_info_sig.sig_algo = DigitallySigned::ECDSA;
  data.segment_info_sig.signature = Sign(treedata);

  assert(!data.segment_info_sig.signature.empty());

  // Currently ignored.
  data.timestamp = time(NULL);

  std::string segment_info = data.SerializeSegmentInfo();

  // Log the segment info.
  db_->WriteSegmentInfo(segment_info);

  // Start a new segment.
  logsegments_.push_back(new MerkleTree(new Sha256Hasher()));
}

std::string TreeLogger::Sign(const std::string &data) {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  assert(EVP_SignInit(&ctx, EVP_sha256()) == 1);
  assert(EVP_SignUpdate(&ctx, data.data(), data.size()) == 1);
  unsigned int sig_size = EVP_PKEY_size(pkey_);
  unsigned char *sig = new unsigned char[sig_size];

  assert(EVP_SignFinal(&ctx, sig, &sig_size, pkey_) == 1);

  EVP_MD_CTX_cleanup(&ctx);
  std::string ret(reinterpret_cast<const char*>(sig), sig_size);

  delete[] sig;
  return ret;
}
