#ifndef CERT_TRANS_TOOLS_CLUSTERTOOL_INL_H_
#define CERT_TRANS_TOOLS_CLUSTERTOOL_INL_H_
#include <event2/thread.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/text_format.h>
#include <memory>
#include <openssl/err.h>
#include <string>

#include "util/etcd.h"
#include "log/etcd_consistent_store.h"
#include "log/logged_certificate.h"
#include "log/log_signer.h"
#include "log/sqlite_db.h"
#include "log/strict_consistent_store.h"
#include "log/tree_signer.h"
#include "proto/ct.pb.h"
#include "tools/clustertool.h"
#include "util/masterelection.h"
#include "util/read_key.h"
#include "util/status.h"
#include "util/thread_pool.h"

namespace cert_trans {

// TODO(alcutter): have a way of passing in other configs
const char kDefaultClusterConfig[] =
    "minimum_serving_nodes: 2\n"
    "minimum_serving_fraction: 0.75\n";


// static
template <class Logged>
util::Status ClusterTool<Logged>::InitLog(
    TreeSigner<Logged>* tree_signer,
    ConsistentStore<Logged>* consistent_store) {
  if (tree_signer->UpdateTree() != TreeSigner<LoggedCertificate>::OK) {
    return util::Status(util::error::UNKNOWN, "Failed to Update Tree");
  }

  util::Status status(
      consistent_store->SetServingSTH(tree_signer->LatestSTH()));
  if (!status.ok()) {
    return status;
  }

  ct::ClusterConfig config;
  if (!google::protobuf::TextFormat::ParseFromString(kDefaultClusterConfig,
                                                     &config)) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Couldn't parse ClusterConfig");
  }
  status = consistent_store->SetClusterConfig(config);
  return status;
}


}  // namespace cert_trans
#endif  // CERT_TRANS_TOOLS_CLUSTERTOOL_INL_H_
