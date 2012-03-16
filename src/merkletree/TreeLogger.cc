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
  ReadDB();
}

// Currently, this rehashes the whole database.
// We could modify MerkleTrees to resume directly from leaf hashes instead.
void TreeLogger::ReadDB() {
  std::string data;
  const size_t segment_count = db_->SegmentCount();
  for (size_t segment = 0; segment < segment_count; ++segment) {
    size_t index = 0;
    MerkleTree *segment_tree = new MerkleTree(new Sha256Hasher());
    while (EntryInfo(segment, index++, &data) ==
           LogDB::LOGGED)
      segment_tree->AddLeaf(data);
    LogSegmentCheckpoint log_segment;
    log_segment.sequence_number = segment;
    log_segment.segment_size = segment_tree->LeafCount();
    log_segment.root = segment_tree->CurrentRoot();
    assert(!log_segment.root.empty());
    logsegments_.push_back(segment_tree);
    std::string treedata = log_segment.SerializeTreeData();
    // Append the tree root and info to the second level tree.
    segment_infos_.AddLeaf(treedata);
  }
  assert(segment_infos_.LeafCount() == segment_count);

  // Finally, see if there's a locked segment we should sign and release.
  if (db_->HasPendingSegment())
      LogSegment();

  assert(!db_->HasPendingSegment());
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
  // Use the hasher of segment_infos_ to derive the key.
  std::string hash = segment_infos_.LeafHash(data);
  assert(!hash.empty());
  LogDB::Status status = db_->WriteEntry(hash, data);

  switch(status) {
  case(LogDB::LOGGED):
  case(LogDB::PENDING):
  case(LogDB::NEW):
    break;
  default:
    assert(false);
  }

  if (key != NULL)
    key->assign(hash);
  return status;
}

LogDB::Status TreeLogger::EntryInfo(size_t segment, size_t index,
                                    std::string *result) {
  return db_->LookupEntry(segment, index, result);
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
  proof->signature = data.log_segment.signature;
  proof->audit_path = logsegments_[segment]->PathToCurrentRoot(index + 1);
  return status;
}

void TreeLogger::LogSegment() {
  // Make a segment. This will simply return if there already is a pending
  // segment.
  db_->MakeSegment();
  size_t sequence_number = db_->PendingSegmentNumber();
  assert(sequence_number == logsegments_.size());
  LogSegmentCheckpoint log_segment;
  log_segment.sequence_number = sequence_number;
  log_segment.segment_size = db_->PendingSegmentSize();

  MerkleTree *segment_tree = new MerkleTree(new Sha256Hasher());

  std::string entry;

  for (size_t i = 0; i < log_segment.segment_size; ++i) {
    assert(db_->PendingSegmentEntry(i, &entry));
    assert(segment_tree->AddLeaf(entry) == i + 1);
  }
  assert(segment_tree->LeafCount() == log_segment.segment_size);
  log_segment.root = segment_tree->CurrentRoot();
  assert(!log_segment.root.empty());

  logsegments_.push_back(segment_tree);

  std::string treedata = log_segment.SerializeTreeData();
  // Append the tree root and info to the second level tree.
  segment_infos_.AddLeaf(treedata);
  assert(segment_infos_.LeafCount() == sequence_number + 1);

  log_segment.signature.hash_algo = DigitallySigned::SHA256;
  log_segment.signature.sig_algo = DigitallySigned::ECDSA;
  log_segment.signature.sig_string = Sign(treedata);

  assert(!log_segment.signature.sig_string.empty());

  LogHeadCheckpoint log_head;
  log_head.sequence_number = sequence_number;
  log_head.root = segment_infos_.CurrentRoot();
  assert(!log_head.root.empty());

  treedata = log_head.SerializeTreeData();
  log_head.signature.hash_algo = DigitallySigned::SHA256;
  log_head.signature.sig_algo = DigitallySigned::ECDSA;
  log_head.signature.sig_string = Sign(treedata);

  assert(!log_head.signature.sig_string.empty());

  SegmentData data;

  // Currently ignored.
  data.timestamp = time(NULL);
  data.log_segment = log_segment;
  data.log_head = log_head;

  std::string segment_info = data.SerializeSegmentInfo();
  db_->WriteSegmentAndInfo(segment_info);
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
