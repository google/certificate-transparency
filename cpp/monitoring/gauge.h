#ifndef CERT_TRANS_MONITORING_GAUGE_H_
#define CERT_TRANS_MONITORING_GAUGE_H_

#include <string>

#include "base/macros.h"
#include "monitoring/metric.h"

namespace cert_trans {

// A metric whose values can go down as well as up (e.g. memory usage.)
template <class... LabelTypes>
class Gauge : public Metric {
 public:
  static Gauge<LabelTypes...>* New(
      const std::string& name,
      const typename NameType<LabelTypes>::name&... label_names,
      const std::string& help);

  virtual double Get(const LabelTypes&...) const = 0;

  virtual void Set(const LabelTypes&... labels, double value) = 0;

 protected:
  Gauge(const std::string& name,
        const typename NameType<LabelTypes>::name&... label_names,
        const std::string& help)
      : Metric(name, {label_names...}, help) {
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(Gauge);
};

}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_GAUGE_H_
