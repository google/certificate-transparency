#ifndef CERT_TRANS_MONITORING_PROMETHEUS_COUNTER_INL_H_
#define CERT_TRANS_MONITORING_PROMETHEUS_COUNTER_INL_H_

#include <glog/logging.h>

namespace cert_trans {

// static
template <class... LabelTypes>
PrometheusCounter<LabelTypes...>* PrometheusCounter<LabelTypes...>::New(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... labels,
    const std::string& help) {
  return new PrometheusCounter(name, labels..., help);
}

template <class... LabelTypes>
PrometheusCounter<LabelTypes...>::PrometheusCounter(
    const std::string& name,
    const typename NameType<LabelTypes>::name&... labels,
    const std::string& help)
    : Counter<LabelTypes...>(name, labels..., help),
      values_(&family_, [](::io::prometheus::client::Metric* m) {
        return m->mutable_counter();
      }) {
  family_.set_name(name);
  family_.set_help(help);
  family_.set_type(::io::prometheus::client::MetricType::COUNTER);
}

template <class... LabelTypes>
double PrometheusCounter<LabelTypes...>::Get(
    const LabelTypes&... labels) const {
  return values_.GetLabelledValue(labels...);
}

template <class... LabelTypes>
void PrometheusCounter<LabelTypes...>::Increment(const LabelTypes&... labels) {
  IncrementBy(labels..., 1);
}

template <class... LabelTypes>
void PrometheusCounter<LabelTypes...>::IncrementBy(const LabelTypes&... labels,
                                                   double amount) {
  CHECK_LE(0, amount);
  std::lock_guard<std::mutex> lock(mutex_);
  values_.SetLabelledValue(this->LabelNames(), labels...,
                           values_.GetLabelledValue(labels...) + amount);
}

}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_PROMETHEUS_COUNTER_INL_H_
