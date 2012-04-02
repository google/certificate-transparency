#!/bin/bash

fail_resume() {

  fail_point=$1
  crash=$2

  ./faildb fail $fail_point $crash
  local retcode=$?
  if [ $retcode -eq 42 ]; then
    echo "Failed to fail at fail point $fail_point"
    return 42
  else
    ./faildb resume
    if [ $? != 0 ]; then
      echo "Failed to resume at fail point $fail_point"
      return 1
    fi
  fi
  return 0
}

loop_all_fail_points() {
   
  crash=$1

  failed_ops=0
  retcode=0
  while [ $retcode -eq 0 ]
  do
    fail_resume $failed_ops $crash
    retcode=$?
    let failed_ops=$failed_ops+1
  done

  if [ $retcode -eq 42 ]; then
    echo "Successfully resumed $failed_ops failed operations."
    echo "PASS."
  else
    echo "Failed operation $failed_ops. FAIL."
  fi
}

echo "Testing failures"
loop_all_fail_points fail
echo "Testing crashes"
loop_all_fail_points crash
