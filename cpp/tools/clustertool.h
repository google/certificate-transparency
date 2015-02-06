#ifndef CERT_TRANS_TOOLS_CLUSTERTOOL_H_
#define CERT_TRANS_TOOLS_CLUSTERTOOL_H_

namespace cert_trans {


template <class Logged>
class ClusterTool {
 public:
  // Initialise a fresh log cluster:
  //  - Creates /serving_sth containing a new STH of size zero
  //  - Creates the /cluster_config entry.
  static util::Status InitLog(TreeSigner<Logged>* tree_signer,
                              ConsistentStore<Logged>* consistent_store);

 private:
  ClusterTool() = default;
};


}  // namespace cert_trans


#endif  // CERT_TRANS_TOOLS_CLUSTERTOOL_H_
