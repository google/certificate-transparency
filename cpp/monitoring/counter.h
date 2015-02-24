#ifndef CERT_TRANS_MONITORING_COUNTER_H_
#define CERT_TRANS_MONITORING_COUNTER_H_

#include <string>

#include "base/macros.h"
#include "monitoring/metric.h"

namespace cert_trans {

// A metric which can only increase (e.g. total_requests_served).
template <class... Labels>
class Counter : public Metric {
 public:
  static Counter<Labels...>* New(
      const std::string& name,
      const typename NameType<Labels>::name&... label_names,
      const std::string& help);

  virtual double Get(const Labels&...) const = 0;

  virtual void Increment(const Labels&... labels) = 0;

  virtual void IncrementBy(const Labels&... labels, double amount) = 0;

 protected:
  Counter(const std::string& name,
          const typename NameType<Labels>::name&... label_names,
          const std::string& help)
      : Metric(name, {label_names...}, help) {
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(Counter);
};

}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_COUNTER_H_
