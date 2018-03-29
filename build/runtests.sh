#!/bin/bash
set -e
getconf _NPROCESSORS_ONLN
${MAKE} -j$(getconf _NPROCESSORS_ONLN) check VERBOSE=1 V=${ENV_VERBOSE}
${MAKE} -C python test
set +e
