#include "tools/clustertool.h"

#include <openssl/err.h>
#include <memory>
#include <string>

#include "proto/ct.pb.h"
#include "util/status.h"

using util::Status;
using ct::ClusterConfig;

namespace cert_trans {


Status InitLog(const ClusterConfig& cluster_config, TreeSigner* tree_signer,
               ConsistentStore* consistent_store) {
  if (tree_signer->UpdateTree() != TreeSigner::OK) {
    return Status(util::error::UNKNOWN, "Failed to Update Tree");
  }

  Status status(consistent_store->SetServingSTH(tree_signer->LatestSTH()));
  if (!status.ok()) {
    return status;
  }

  return SetClusterConfig(cluster_config, consistent_store);
}


Status SetClusterConfig(const ClusterConfig& cluster_config,
                        ConsistentStore* consistent_store) {
  if (cluster_config.etcd_reject_add_pending_threshold() < 0) {
    return Status(util::error::INVALID_ARGUMENT,
                  "etcd_reject_add_pending_threshold cannot be less than 0");
  }
  return consistent_store->SetClusterConfig(cluster_config);
}


}  // namespace cert_trans
