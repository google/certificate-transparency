#ifndef CERT_TRANS_NET_URL_H_
#define CERT_TRANS_NET_URL_H_

#include <stdint.h>
#include <string>

namespace cert_trans {


class URL {
 public:
  URL() : port_(0) {
  }

  explicit URL(const std::string& url);

  const std::string& Protocol() const {
    return protocol_;
  }

  const std::string& Host() const {
    return host_;
  }

  uint16_t Port() const {
    return port_;
  }

  const std::string& Path() const {
    return path_;
  }

  const std::string& Query() const {
    return query_;
  }

  std::string PathQuery() const;

  void SetPath(const std::string& path) {
    path_ = path;
  }

 private:
  std::string protocol_;
  std::string host_;
  uint16_t port_;
  std::string path_;
  std::string query_;
};


}  // namespace cert_trans

#endif  // CERT_TRANS_NET_URL_H_
