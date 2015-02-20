#include "monitoring/registry.h"

#include <glog/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>

#include "monitoring/monitoring.h"
#include "util/testing.h"

namespace cert_trans {

using std::ostringstream;
using std::string;
using std::unique_ptr;
using std::set;
using testing::AllOf;
using testing::AnyOf;
using testing::Contains;


class RegistryTest : public ::testing::Test {
 public:
  void TearDown() {
    Registry::Instance()->ResetForTestingOnly();
  }

 protected:
  const set<const Metric*>& GetMetrics() {
    return Registry::Instance()->metrics_;
  }

  string SerializeMetric(const Metric& m) {
    ostringstream oss;
    m.Export(&oss);
    return oss.str();
  }
};


TEST_F(RegistryTest, TestAddMetric) {
  unique_ptr<PrometheusCounter<>> counter(
      PrometheusCounter<>::New("name", "help"));
  unique_ptr<PrometheusGauge<>> gauge(PrometheusGauge<>::New("name", "help"));
  EXPECT_EQ(2, GetMetrics().size());
  EXPECT_THAT(GetMetrics(),
              AllOf(Contains(counter.get()), Contains(gauge.get())));
}


TEST_F(RegistryTest, TestExport) {
  unique_ptr<PrometheusCounter<>> counter(
      PrometheusCounter<>::New("name", "help"));
  counter->Increment();

  unique_ptr<PrometheusGauge<>> gauge(PrometheusGauge<>::New("name", "help"));
  gauge->Set(234);

  ostringstream oss;
  Registry::Instance()->Export(&oss);
  EXPECT_THAT(oss.str(),
              AnyOf(SerializeMetric(*counter) + SerializeMetric(*gauge),
                    SerializeMetric(*gauge) + SerializeMetric(*counter)));
}


TEST_F(RegistryTest, TestExportWithUpdate) {
  unique_ptr<PrometheusCounter<>> counter(
      PrometheusCounter<>::New("name", "help"));
  counter->Increment();

  unique_ptr<PrometheusGauge<>> gauge(PrometheusGauge<>::New("name", "help"));
  gauge->Set(234);

  const string counter_pre(SerializeMetric(*counter));
  const string gauge_pre(SerializeMetric(*gauge));
  {
    ostringstream oss;
    Registry::Instance()->Export(&oss);
    EXPECT_THAT(oss.str(),
                AnyOf(counter_pre + gauge_pre, gauge_pre + counter_pre));
  }

  counter->IncrementBy(100);
  gauge->Set(567);

  {
    const string counter_post(SerializeMetric(*counter));
    const string gauge_post(SerializeMetric(*gauge));
    EXPECT_NE(counter_pre, counter_post);
    EXPECT_NE(gauge_pre, gauge_post);

    ostringstream oss;
    Registry::Instance()->Export(&oss);
    EXPECT_THAT(oss.str(),
                AnyOf(counter_post + gauge_post, gauge_post + counter_post));
  }
}


}  // namespace cert_trans


int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
