#ifndef CERT_TRANS_FETCHER_FETCHER_H_
#define CERT_TRANS_FETCHER_FETCHER_H_

#include <memory>

#include "fetcher/peer_group.h"
#include "log/database.h"
#include "log/logged_certificate.h"
#include "util/task.h"

namespace cert_trans {


void FetchLogEntries(Database<LoggedCertificate>* db,
                     std::unique_ptr<PeerGroup>&& peer_group,
                     util::Task* task);


}  // namespace cert_trans

#endif  // CERT_TRANS_FETCHER_FETCHER_H_
