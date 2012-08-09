#ifndef LOGDBTESTCONSTANTS_H
#define LOGDBTESTCONSTANTS_H

#include <stddef.h>

#include "../include/types.h"

namespace logdbtest {

extern const size_t kNumberOfSegments;
extern const size_t kLogSize;
extern const size_t kSegmentSizes[];
extern const byte kEntries[][20];
extern const byte kKeys[][8];
extern const byte kSegmentInfos[][10];

} // logdbtest

#endif
