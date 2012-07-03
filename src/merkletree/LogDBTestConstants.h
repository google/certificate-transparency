#ifndef LOGDBTESTCONSTANTS_H
#define LOGDBTESTCONSTANTS_H

#include <stddef.h>

namespace logdbtest {

extern const size_t kNumberOfSegments;
extern const size_t kLogSize;
extern const size_t kSegmentSizes[];
extern const unsigned char kEntries[][20];
extern const unsigned char kKeys[][8];
extern const unsigned char kSegmentInfos[][10];

} // logdbtest

#endif
