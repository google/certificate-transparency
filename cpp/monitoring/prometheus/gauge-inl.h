#ifndef CERT_TRANS_MONITORING_PROMETHEUS_GAUGE_INL_H_
#define CERT_TRANS_MONITORING_PROMETHEUS_GAUGE_INL_H_

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
      values_(&family_, [](::io::prometheus::client::Metric* m) {
        return m->mutable_gauge();
      }) {
  family_.set_name(name);
  family_.set_help(help);
  family_.set_type(::io::prometheus::client::MetricType::GAUGE);
}

template <class... LabelTypes>
double PrometheusGauge<LabelTypes...>::Get(const LabelTypes&... labels) const {
  return values_.GetLabelledValue(labels...);
}

template <class... LabelTypes>
void PrometheusGauge<LabelTypes...>::Set(const LabelTypes&... labels,
                                         double amount) {
  return values_.SetLabelledValue(this->LabelNames(), labels..., amount);
}

}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_PROMETHEUS_GAUGE_INL_H_
