#ifndef CERT_TRANS_MONITORING_PROMETHEUS_GAUGE_INL_H_
#define CERT_TRANS_MONITORING_PROMETHEUS_GAUGE_INL_H_

#include <glog/logging.h>

#include "util/protobuf_util.h"

namespace cert_trans {

// static
template <class... LabelTypes>
PrometheusGauge<LabelTypes...>* PrometheusGauge<LabelTypes...>::New(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... labels,
    const std::string& help) {
  return new PrometheusGauge(name, labels..., help);
}


template <class... LabelTypes>
PrometheusGauge<LabelTypes...>::PrometheusGauge(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... labels,
    const std::string& help)
    : Gauge<LabelTypes...>(name, labels..., help),
      values_(&family_, &::io::prometheus::client::Metric::mutable_gauge,
              &::io::prometheus::client::Metric::gauge) {
  family_.set_name(name);
  family_.set_help(help);
  family_.set_type(::io::prometheus::client::MetricType::GAUGE);
}


template <class... LabelTypes>
void PrometheusGauge<LabelTypes...>::Export(std::ostream* os) const {
  std::lock_guard<std::mutex> lock(mutex_);
  CHECK(WriteDelimitedToOstream(family_, os));
}


template <class... LabelTypes>
void PrometheusGauge<LabelTypes...>::ExportText(std::ostream* os) const {
  std::lock_guard<std::mutex> lock(mutex_);
  *os << family_.DebugString();
}


template <class... LabelTypes>
double PrometheusGauge<LabelTypes...>::Get(const LabelTypes&... labels) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return values_.GetLabelledValue(labels...);
}


template <class... LabelTypes>
void PrometheusGauge<LabelTypes...>::Set(const LabelTypes&... labels,
                                         double amount) {
  std::lock_guard<std::mutex> lock(mutex_);
  return values_.SetLabelledValue(this->LabelNames(), labels..., amount);
}


}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_PROMETHEUS_GAUGE_INL_H_
