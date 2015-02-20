#include "monitoring/registry.h"
#include "monitoring/metric.h"

namespace cert_trans {

// static
Registry* Registry::Instance() {
  static Registry* registry(new Registry);
  return registry;
}


void Registry::AddMetric(const Metric* metric) {
  std::lock_guard<std::mutex> lock(mutex_);
  metrics_.insert(metric);
}


void Registry::ResetForTestingOnly() {
  std::lock_guard<std::mutex> lock(mutex_);
  metrics_.clear();
}


void Registry::Export(std::ostream* os) const {
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto* m : metrics_) {
    m->Export(os);
  }
}


void Registry::ExportHTML(std::ostream* os) const {
  std::lock_guard<std::mutex> lock(mutex_);
  *os << "<html>\n"
      << "<body>\n"
      << "  <h1>Metrics</h1>\n";

  *os << "<table>\n";
  bool bg_flip(false);
  for (const auto* m : metrics_) {
    *os << "<tr><td style='background-color:#"
        << (bg_flip ? "bbffbb" : "eeffee") << "'><code>\n";
    bg_flip = !bg_flip;
    m->ExportText(os);
    *os << "\n</code></td></tr>\n";
  }
  *os << "</table>\n"
      << "</body>\n"
      << "</html>\n";
}


}  // namespace cert_trans
