#include <assert.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10000000
# error "Need OpenSSL >= 1.0.0"
#endif
#include <stddef.h>
#include <time.h>
#include <vector>

#include "../include/types.h"
#include "LogDB.h"
#include "LogRecord.h"
#include "MerkleTree.h"
#include "SerialHasher.h"
#include "TreeLogger.h"

TreeLogger::TreeLogger(LogDB *db, EVP_PKEY *pkey)
    : db_(db),
      pkey_(pkey),
      // Default handler.
      handler_(new SubmissionHandler()),
      segment_infos_(new Sha256Hasher()) {
  // For now, the signature and hash algorithms are hard-coded.
  assert(pkey_ != NULL && pkey_->type == EVP_PKEY_EC);
  assert(db_ != NULL);
  ReadDB();
}

TreeLogger::TreeLogger(LogDB *db, EVP_PKEY *pkey, SubmissionHandler *handler)
    : db_(db),
      pkey_(pkey),
      handler_(handler),
      segment_infos_(new Sha256Hasher()) {
  // For now, the signature and hash algorithms are hard-coded.
  assert(pkey_ != NULL && pkey_->type == EVP_PKEY_EC);
  assert(db_ != NULL);
  assert(handler_ != NULL);
  ReadDB();
}

// Currently, this rehashes the whole database.
// We could modify MerkleTrees to resume directly from leaf hashes instead.
void TreeLogger::ReadDB() {
  bstring data;
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
    bstring treedata = log_segment.SerializeTreeData();
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
  delete handler_;
}

LogDB::Status TreeLogger::QueueEntry(const bstring &data, bstring *key) {
  return QueueEntry(LogEntry::TEST_ENTRY, data, key);
}

LogDB::Status TreeLogger::QueueEntry(LogEntry::LogEntryType type,
                                     const bstring &data, bstring *key) {
  // Verify the submission and compute signed and unsigned parts.
  LogEntry *entry = handler_->ProcessSubmission(type, data);
  if (entry == NULL)
    return LogDB::REJECTED;
  // First check whether the entry already exists.
  // Use the hasher of segment_infos_ to derive the key.
  bstring record;
  if (!entry->Serialize(&record))
    return LogDB::REJECTED;
  assert(!record.empty());
  bstring signed_part;
  bool ret = entry->SerializeSigned(&signed_part);
  assert(ret);
  assert(!signed_part.empty());
  delete entry;

  bstring hash = segment_infos_.LeafHash(signed_part);
  assert(!hash.empty());
  LogDB::Status status = db_->WriteEntry(hash, record);

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
                                    bstring *result) {
  return db_->LookupEntry(segment, index, result);
}

LogDB::Status TreeLogger::EntryInfo(const bstring &key, LogDB::Lookup type,
                                    bstring *result) {
  return db_->LookupEntry(key, type, result);
}

LogDB::Status TreeLogger::SegmentInfo(size_t index, bstring *result) {
  return db_->LookupSegmentInfo(index, result);
}

LogDB::Status TreeLogger::EntryAuditProof(const bstring &key,
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
  bstring segment_info;
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

  for (size_t i = 0; i < log_segment.segment_size; ++i) {
    bstring record;
    LogDB::Status status = db_->PendingSegmentEntry(i, &record);
    assert(status == LogDB::PENDING);
    LogEntry *entry = LogEntry::Deserialize(record);
    assert(entry != NULL);
    bstring signed_part;
    bool ret = entry->SerializeSigned(&signed_part);
    assert(ret);
    assert(!signed_part.empty());
    assert(segment_tree->AddLeaf(signed_part) == i + 1);
    delete entry;
  }
  assert(segment_tree->LeafCount() == log_segment.segment_size);
  log_segment.root = segment_tree->CurrentRoot();
  assert(!log_segment.root.empty());

  logsegments_.push_back(segment_tree);

  bstring treedata = log_segment.SerializeTreeData();
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

  bstring segment_info = data.SerializeSegmentInfo();
  db_->WriteSegmentAndInfo(segment_info);
}

bstring TreeLogger::Sign(const bstring &data) {
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);
  // NOTE: this syntax for setting the hash function requires OpenSSL >= 1.0.0.
  assert(EVP_SignInit(&ctx, EVP_sha256()) == 1);
  assert(EVP_SignUpdate(&ctx, data.data(), data.size()) == 1);
  unsigned int sig_size = EVP_PKEY_size(pkey_);
  unsigned char *sig = new unsigned char[sig_size];

  assert(EVP_SignFinal(&ctx, sig, &sig_size, pkey_) == 1);

  EVP_MD_CTX_cleanup(&ctx);
  bstring ret(sig, sig_size);

  delete[] sig;
  return ret;
}
