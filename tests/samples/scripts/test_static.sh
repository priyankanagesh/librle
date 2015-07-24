#!/bin/bash

# Static test script.

# Arguments:
# $1: Test binary
# $2: Pcaps folder

if [[ $# -ne 2 ]]; then
    echo "Error, two arguments needed, the test binary and the pcaps folder." 
    exit
fi

echo "[`basename ${1}`] Checking folder \"`basename ${2}`\""

echo "`find ${2} -name "*.pcap" | wc -l` PCAP traces..."

# For each pcap file in pcaps folder, the pcap is used as an argument of our test.
# Error outputs are collected and counted.
#
# Return '0' if Ok, else number of errors counted.
count_error () {
find ${2} -name "*.pcap" \
    -exec sh -c "${1} --ignore-malformed '{}' > /dev/null ; echo  $?" \; \
    | grep "1" \
    | wc -l
}

# Return 0 if no errors are counted, else 1
eval_errors () {
    if [[ ${1} -eq 0 ]]; then
        echo "OK"
    fi
    [[ ${1} -eq 0 ]]
}


eval_errors `count_error ${1} ${2}`
