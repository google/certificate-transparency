#ifndef CERT_TRANS_MONITORING_PROMETHEUS_LABELLED_VALUES_H_
#define CERT_TRANS_MONITORING_PROMETHEUS_LABELLED_VALUES_H_

#include <chrono>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "base/macros.h"
#include "monitoring/prometheus/metrics.pb.h"

namespace cert_trans {
namespace {


// Some variadic function magic to apply an arbitrary number of labels to the
// passed in |metric|.
// These two functions work in tandem, this first one is for the case where
// there are 0 args (and hence doesn't do anything other than terminate the
// recursion, and let the code compile when there are 0 labels.)
template <class... LabelTypes>
void AddLabelTypes(::io::prometheus::client::Metric* metric, int i,
                   const std::vector<std::string>& names) {
  // nop
}

// This second function actually sets labels, calling like so:
//   AddLabelTypes(m, 0, names, labels...);
// results in the first entry in |labels| being "peeled off", with the
// remaining entries in |remaining| (think functional programming), and
// recurses if |remaining| isn't empty.
template <class First, class... RemainingLabelTypes>
void AddLabelTypes(::io::prometheus::client::Metric* metric, int i,
                   const std::vector<std::string>& names, First first,
                   RemainingLabelTypes... remaining) {
  ::io::prometheus::client::LabelPair* label_pair(metric->add_label());
  label_pair->set_name(names[i]);
  std::ostringstream oss;
  oss << first;
  label_pair->set_value(oss.str());
  // When remaining... is empty, we'll call into the function above and
  // terminate the recursion.
  return AddLabelTypes(metric, ++i, names, remaining...);
}


}  // namespace


namespace internal {


// TODO(alcutter): consider templating the value type.  Prometheus is all
// doubles at the proto level anyway, but it's a little weird to see a
// Counter<double> for total_num_requests for example.
template <class MetricType, class... LabelTypes>
class LabelledValues {
 public:
  typedef std::function<MetricType*(io::prometheus::client::Metric*)>
      MutableMetricFunc;


  LabelledValues(io::prometheus::client::MetricFamily* family,
                 const MutableMetricFunc& get_mutable_value)
      : family_(family), get_mutable_value_(get_mutable_value) {
  }


  double GetLabelledValue(const LabelTypes&... labels) const {
    const std::tuple<LabelTypes...> key(labels...);
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it(metrics_.find(key));
    if (it == metrics_.end()) {
      return 0;
    }

    return it->second->counter().value();
  }


  void SetLabelledValue(const std::vector<std::string>& label_names,
                        const LabelTypes&... labels, double amount) {
    const std::tuple<LabelTypes...> key(labels...);
    io::prometheus::client::Metric* metric(nullptr);

    std::lock_guard<std::mutex> lock(mutex_);
    const auto it(metrics_.find(key));
    if (it == metrics_.end()) {
      metric = family_->add_metric();
      AddLabelTypes(metric, 0, label_names, labels...);
      metrics_.insert(std::make_pair(key, metric));
    } else {
      metric = it->second;
    }
    metric->mutable_counter()->set_value(amount);
    const auto duration_since_epoch(
        std::chrono::system_clock().now().time_since_epoch());
    metric->set_timestamp_ms(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            duration_since_epoch).count());
  }


 private:
  mutable std::mutex mutex_;
  io::prometheus::client::MetricFamily* family_;
  const MutableMetricFunc get_mutable_value_;
  // cache of known Metrics by label:
  std::map<std::tuple<LabelTypes...>, io::prometheus::client::Metric*>
      metrics_;

  DISALLOW_COPY_AND_ASSIGN(LabelledValues);
};


}  // namespace internal
}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_PROMETHEUS_LABELLED_VALUES_H_
