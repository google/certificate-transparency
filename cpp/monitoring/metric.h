#ifndef CERT_TRANS_MONITORING_METRIC_H_
#define CERT_TRANS_MONITORING_METRIC_H_

#include <string>
#include <vector>

#include "base/macros.h"

namespace cert_trans {

// As pointless as this looks, it's crucial in order to be able to specify that
// we want as many |name| typed args as there are LabelTypes... in the Metric
// class below.
template <class... F>
struct NameType {
  typedef const std::string& name;
};


// Base class for all metric types
template <class... LabelTypes>
class Metric {
 protected:
  Metric(const std::string& name,
         const typename NameType<LabelTypes>::name&... label_names,
         const std::string& help)
      : name_(name), label_names_{label_names...}, help_(help) {
  }

  virtual ~Metric() = default;

  // Returns the name of this metric
  const std::string& Name() const {
    return name_;
  }

  // Returns the name of each of the labels this metric has, in the same order
  // as the LabelTypes were specified.
  const std::vector<std::string>& LabelNames() const {
    return label_names_;
  }

  // Returns the i'th label name.
  const std::string& LabelName(size_t i) const {
    return label_names_[i];
  }

  // Returns the help string associated with this metric.
  const std::string& Help() const {
    return help_;
  }

 private:
  const std::string name_;
  const std::vector<std::string> label_names_;
  const std::string help_;

  friend class CounterTest;
  friend class GaugeTest;

  DISALLOW_COPY_AND_ASSIGN(Metric);
};

}  // namespace cert_trans

#endif  // CERT_TRANS_MONITORING_METRIC_H_
