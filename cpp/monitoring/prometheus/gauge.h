#ifndef CERT_TRANS_MONITORING_PROMETHEUS_GAUGE_H_
#define CERT_TRANS_MONITORING_PROMETHEUS_GAUGE_H_

#include "monitoring/gauge.h"

#include <mutex>
#include <string>

#include "base/macros.h"
#include "monitoring/prometheus/labelled_values.h"
#include "monitoring/prometheus/metrics.pb.h"

namespace cert_trans {

template <class... LabelTypes>
class PrometheusGauge : public Gauge<LabelTypes...> {
 public:
  static PrometheusGauge<LabelTypes...>* New(
      const std::string& name,
      const typename NameType<LabelTypes>::name&... labels,
      const std::string& help);

  void Export(std::ostream* os) const override;

  void ExportText(std::ostream* os) const override;

  double Get(const LabelTypes&...) const override;

  void Set(const LabelTypes&... labels, double value) override;

 private:
  PrometheusGauge(const std::string& name,
                  const typename NameType<LabelTypes>::name&... labels,
                  const std::string& help);

  mutable std::mutex mutex_;
  ::io::prometheus::client::MetricFamily family_;
  internal::LabelledValues<::io::prometheus::client::Gauge, LabelTypes...>
      values_;

  DISALLOW_COPY_AND_ASSIGN(PrometheusGauge);
};

}  // namespace cert_trans

#include "monitoring/prometheus/gauge-inl.h"

#endif  // CERT_TRANS_MONITORING_PROMETHEUS_GAUGE_H_
