#ifndef CERT_TRANS_MONITORING_PROMETHEUS_COUNTER_H_
#define CERT_TRANS_MONITORING_PROMETHEUS_COUNTER_H_

#include "monitoring/counter.h"

#include <mutex>
#include <string>

#include "base/macros.h"
#include "monitoring/prometheus/labelled_values.h"
#include "monitoring/prometheus/metrics.pb.h"

namespace cert_trans {

template <class... LabelTypes>
class PrometheusCounter : public Counter<LabelTypes...> {
 public:
  static PrometheusCounter<LabelTypes...>* New(
      const std::string& name,
      const typename NameType<LabelTypes>::name&... labels,
      const std::string& help);

  void Export(std::ostream* os) const override;

  void ExportText(std::ostream* os) const override;

  double Get(const LabelTypes&...) const override;

  void Increment(const LabelTypes&... labels) override;

  void IncrementBy(const LabelTypes&... labels, double amount) override;

 private:
  PrometheusCounter(const std::string& name,
                    const typename NameType<LabelTypes>::name&... labels,
                    const std::string& help);

  mutable std::mutex mutex_;
  ::io::prometheus::client::MetricFamily family_;
  internal::LabelledValues<::io::prometheus::client::Counter, LabelTypes...>
      values_;

  DISALLOW_COPY_AND_ASSIGN(PrometheusCounter);
};

}  // namespace cert_trans

#include "monitoring/prometheus/counter-inl.h"

#endif  // CERT_TRANS_MONITORING_PROMETHEUS_COUNTER_H_
