#ifndef CERT_TRANS_UTIL_TESTING_H_
#define CERT_TRANS_UTIL_TESTING_H_

#include <gflags/gflags.h>

DECLARE_string(test_srcdir);

namespace cert_trans {
namespace test {

void InitTesting(const char* name, int* argc, char*** argv, bool remove_flags);

}  // namespace test
}  // namespace cert_trans

#endif  // CERT_TRANS_UTIL_TESTING_H_
