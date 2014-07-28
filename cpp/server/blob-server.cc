/* -*- indent-tabs-mode: nil -*- */

#include <fstream>
#include <gflags/gflags.h>
#include <iostream>
#include <openssl/ssl.h>

#include "log/database.h"
#include "log/log_lookup.h"
#include "log/log_signer.h"
#include "log/sqlite_db.h"
#include "log/tree_signer.h"
#include "server/event.h"
#include "server/logged_blob.h"

// TODO(benl): Make this client/server, make a configurable server
// (and client?) pipeline which this shares with ct-server.

using google::RegisterFlagValidator;
using std::string;

DEFINE_string(key, "", "PEM-encoded server private key file");
DEFINE_string(db, "", "SQLite database for certificate and tree storage");
DEFINE_string(proof, "", "Destination for audit proof");
DEFINE_string(sth, "", "Destination for signed tree head");

static bool ValidateRead(const char *flagname, const string &path) {
  if (access(path.c_str(), R_OK) != 0) {
    std::cout << "Cannot access " << flagname << " at " << path << std::endl;
    return false;
  }
  return true;
}

static const bool key_dummy = RegisterFlagValidator(&FLAGS_key,
                                                    &ValidateRead);

static bool ValidateNonexistent(const char *flagname, const string &path) {
  if (access(path.c_str(), R_OK) == 0 || access(path.c_str(), W_OK) == 0
      || errno != ENOENT) {
    std::cout << flagname << " at " << path << " already exists" << std::endl;
    return false;
  }
  return true;
}

static const bool proof_dummy = RegisterFlagValidator(&FLAGS_proof,
                                                      &ValidateNonexistent);

static const bool sth_dummy = RegisterFlagValidator(&FLAGS_sth,
                                                    &ValidateNonexistent);

// TreeSigners are expensive to make, so only make one.
static TreeSigner<LoggedBlob> *GetTreeSigner(Database<LoggedBlob> *db) {
  static TreeSigner<LoggedBlob> *tree_signer = NULL;

  if (tree_signer == NULL) {
    EVP_PKEY *pkey = NULL;
    CHECK_EQ(Services::ReadPrivateKey(&pkey, FLAGS_key), Services::KEY_OK);
    tree_signer = new TreeSigner<LoggedBlob>(db, new LogSigner(pkey));
  }

  return tree_signer;
}

// TODO: make this into a fully functional blob server/client pair.
int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  SSL_library_init();

  const char *blobfile = argv[1];

  std::ifstream blobf(blobfile, std::ios::binary);

  blobf.seekg(0, std::ios::end);
  size_t length = blobf.tellg();
  blobf.seekg(0, std::ios::beg);
  char *buffer = new char[length + 1];
  blobf.read(buffer,length + 1);
  blobf.close();
  CHECK(blobf.eof());

  std::string blob(buffer, length);
  delete[] buffer;

  LoggedBlob logged_blob(blob);

  Database<LoggedBlob> *db = new SQLiteDB<LoggedBlob>(FLAGS_db);

  Database<LoggedBlob>::LookupResult db_result
      = db->LookupByHash(logged_blob.Hash());
  if (db_result == Database<LoggedBlob>::LOOKUP_OK) {
    std::cout << "Entry already exists" << std::endl;
  } else {
    std::cout << "Adding new entry" << std::endl;

    db->CreatePendingEntry(logged_blob);

    CHECK_EQ(GetTreeSigner(db)->UpdateTree(), TreeSigner<LoggedBlob>::OK);
  }

  if (!FLAGS_proof.empty()) {
    LogLookup<LoggedBlob> lookup(db);
    ct::MerkleAuditProof proof;
    std::string serialized_leaf;
    logged_blob.SerializeForLeaf(&serialized_leaf);

    // FIXME(benl): one of these already exists somewhere - either
    // hoist it or expose it.
    TreeHasher tree_hasher(new Sha256Hasher());
    LogLookup<LoggedBlob>::LookupResult lu_result
        = lookup.AuditProof(tree_hasher.HashLeaf(serialized_leaf), &proof);
    CHECK_EQ(lu_result, LogLookup<LoggedBlob>::OK);

    std::string proof_str;
    CHECK(proof.SerializeToString(&proof_str));

    std::ofstream proof_file(FLAGS_proof.c_str(), std::ios::binary);
    proof_file.write(proof_str.data(), proof_str.length());
    CHECK(!proof_file.bad());
  }

  if (!FLAGS_sth.empty()) {
    const ct::SignedTreeHead &sth = GetTreeSigner(db)->LatestSTH();

    std::string sth_str;
    CHECK(sth.SerializeToString(&sth_str));

    std::ofstream sth_file(FLAGS_sth.c_str(), std::ios::binary);
    sth_file.write(sth_str.data(), sth_str.length());
    CHECK(!sth_file.bad());
  }

}
