#ifndef CERT_TRANS_MONITORING_PROMETHEUS_PROMETHEUS_H_
#define CERT_TRANS_MONITORING_PROMETHEUS_PROMETHEUS_H_

#include "monitoring/prometheus/counter.h"
#include "monitoring/prometheus/gauge.h"

namespace cert_trans {

template <class... LabelTypes>
Gauge<LabelTypes...>* Gauge<LabelTypes...>::New(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... label_names,
    const std::string& help) {
  return new PrometheusGauge<LabelTypes...>(name, label_names..., help);
}

template <class... LabelTypes>
Counter<LabelTypes...>* Counter<LabelTypes...>::New(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... label_names,
    const std::string& help) {
  return new PrometheusCounter<LabelTypes...>(name, label_names..., help);
}

}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_PROMETHEUS_PROMETHEUS_H_
