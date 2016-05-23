#ifndef CERT_TRANS_TOOLS_CLUSTERTOOL_H_
#define CERT_TRANS_TOOLS_CLUSTERTOOL_H_

#include "log/consistent_store.h"
#include "log/logged_entry.h"
#include "log/tree_signer.h"

namespace ct {
class ClusterConfig;
}  // namespace ct

namespace util {
class Status;
}  // namespace util

namespace cert_trans {


// Initialise a fresh log cluster:
//  - Creates /serving_sth containing a new STH of size zero
//  - Creates the /cluster_config entry.
util::Status InitLog(const ct::ClusterConfig& cluster_config,
                     TreeSigner* tree_signer,
                     ConsistentStore* consistent_store);

// Sets the cluster config
util::Status SetClusterConfig(const ct::ClusterConfig& cluster_config,
                              ConsistentStore* consistent_store);


}  // namespace cert_trans


#endif  // CERT_TRANS_TOOLS_CLUSTERTOOL_H_
