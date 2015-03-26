#ifndef CERT_TRANS_UTIL_ETCD_DELETE_H_
#define CERT_TRANS_UTIL_ETCD_DELETE_H_

#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include "util/etcd.h"

namespace cert_trans {


void EtcdDeleteKeys(EtcdClient* client,
                    std::vector<std::pair<std::string, int64_t>>&& keys,
                    util::Task* task);


}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_ETCD_DELETE_H_
