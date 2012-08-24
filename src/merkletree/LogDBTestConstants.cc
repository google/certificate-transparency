#include "log_db_test_constants.h"
#include "types.h"

namespace logdbtest {

const size_t kNumberOfSegments = 4;
const size_t kLogSize = 15;
const size_t kSegmentSizes[4] = { 5, 2, 0, 8 };
// Nice human-readable test entries for easier debugging.
const byte kEntries[15][20] = {
  // Segment 1
  "Angelfish", "Bananafish", "Unicorn fish", "Upside-down catfish",
  "Weasel shark",
  // Segment 2
  "Arsenic", "Cyanide",
  // Segment 3 is empty
  // Segment 4
  "0", "1", "2", "3", "4", "5", "6", "7"
};

const byte kKeys[15][8] = {
  "abcdef0", "abcdef1", "xyzabc2", "zyxabc3", "ijklmn4", "jklmni5", "klmnij6",
  "lmnijk7", "mnijkl8", "nijklm9", "opqrs10", "wxyza11", "gfedc12", "gfedc13",
  "gfedc14"
};

const byte kSegmentInfos[4][10] = { "Fish", "Poison", "Empty", "Sequence" };

} // logdbtest
