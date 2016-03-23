#!/bin/bash

# Special static test script.

# Arguments:
# $1: Test binary
# $2: Pcap file
# $3: arguments

if [[ $# -ne 3 ]]; then
    echo "Error, three arguments needed, the test binary, the arguments and the pcaps file." 
    exit
fi

echo "[`basename ${1}`] Special test on \"`basename ${2}`\" with argument \"-${3}\""

# For each pcap file in pcaps folder, the pcap is used as an argument of our test.
# Error outputs are collected and counted.
#
# Return '0' if Ok, else number of errors counted.
count_error () {
sh -c "${1} --ignore-malformed -${3} ${2}" \
    | grep "exit code 1" \
    | wc -l
}

# Return 0 if no errors are counted, else 1
eval_errors () {
    if [[ ${1} -eq 0 ]]; then
        echo "OK"
    fi
    [[ ${1} -eq 0 ]]
}

eval_errors `count_error ${1} ${2} ${3}`
