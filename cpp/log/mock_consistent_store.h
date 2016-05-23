#ifndef CERT_TRANS_LOG_MOCK_CONSISTENT_STORE_H_
#define CERT_TRANS_LOG_MOCK_CONSISTENT_STORE_H_

#include <gmock/gmock.h>

#include "log/consistent_store.h"

namespace cert_trans {

class MockConsistentStore : public ConsistentStore {
 public:
  MOCK_CONST_METHOD0_T(NextAvailableSequenceNumber, util::StatusOr<int64_t>());

  MOCK_METHOD1_T(SetServingSTH, util::Status(const ct::SignedTreeHead&));

  MOCK_CONST_METHOD0_T(GetServingSTH, util::StatusOr<ct::SignedTreeHead>());

  MOCK_METHOD1_T(AddPendingEntry, util::Status(LoggedEntry* entry));

  MOCK_CONST_METHOD2_T(GetPendingEntryForHash,
                       util::Status(const std::string& hash,
                                    EntryHandle<LoggedEntry>* entry));

  MOCK_CONST_METHOD1_T(
      GetPendingEntries,
      util::Status(std::vector<EntryHandle<LoggedEntry>>* entries));

  MOCK_CONST_METHOD1_T(
      GetSequenceMapping,
      util::Status(EntryHandle<ct::SequenceMapping>* mapping));

  MOCK_METHOD1_T(UpdateSequenceMapping,
                 util::Status(EntryHandle<ct::SequenceMapping>* mapping));

  MOCK_CONST_METHOD0_T(GetClusterNodeState,
                       util::StatusOr<ct::ClusterNodeState>());

  MOCK_METHOD1_T(SetClusterNodeState,
                 util::Status(const ct::ClusterNodeState& state));

  MOCK_METHOD2_T(WatchServingSTH,
                 void(const ConsistentStore::ServingSTHCallback& cb,
                      util::Task* task));

  MOCK_METHOD2_T(WatchClusterNodeStates,
                 void(const ConsistentStore::ClusterNodeStateCallback& cb,
                      util::Task* task));

  MOCK_METHOD2_T(WatchClusterConfig,
                 void(const ConsistentStore::ClusterConfigCallback& cb,
                      util::Task* task));

  MOCK_METHOD1(SetClusterConfig, util::Status(const ct::ClusterConfig&));

  MOCK_METHOD0(CleanupOldEntries, util::StatusOr<int64_t>());
};

}  // namespace cert_log


#endif  // CERT_TRANS_LOG_MOCK_CONSISTENT_STORE_H_
