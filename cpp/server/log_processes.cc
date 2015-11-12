#include "server/log_processes.h"

#include <chrono>
#include <functional>
#include <gflags/gflags.h>

#include "monitoring/latency.h"
#include "monitoring/monitoring.h"
#include "server/metrics.h"

DEFINE_int32(sequencing_frequency_seconds, 10,
             "How often should new entries be sequenced. The sequencing runs "
             "in parallel with the tree signing and cleanup.");

using cert_trans::Counter;
using cert_trans::Latency;
using std::function;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::steady_clock;

namespace {

Counter<bool>* sequencer_total_runs = Counter<bool>::New(
    "sequencer_total_runs", "successful",
    "Total number of sequencer runs broken out by success.");
Latency<milliseconds> sequencer_sequence_latency_ms(
    "sequencer_sequence_latency_ms",
    "Total time spent sequencing entries by sequencer");
}

namespace cert_trans {
void SequenceEntries(TreeSigner<LoggedEntry>* tree_signer,
                     const function<bool()>& is_master) {
  CHECK_NOTNULL(tree_signer);
  CHECK(is_master);
  const steady_clock::duration period(
      (seconds(FLAGS_sequencing_frequency_seconds)));
  steady_clock::time_point target_run_time(steady_clock::now());

  while (true) {
    if (is_master()) {
      const ScopedLatency sequencer_sequence_latency(
          sequencer_sequence_latency_ms.GetScopedLatency());
      util::Status status(tree_signer->SequenceNewEntries());
      if (!status.ok()) {
        LOG(WARNING) << "Problem sequencing new entries: " << status;
      }
      sequencer_total_runs->Increment(status.ok());
    }

    const steady_clock::time_point now(steady_clock::now());
    while (target_run_time <= now) {
      target_run_time += period;
    }

    std::this_thread::sleep_for(target_run_time - now);
  }
}

}  // namespace cert_trans
