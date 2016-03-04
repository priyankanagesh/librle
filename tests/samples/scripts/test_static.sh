#!/bin/bash

# Static test script.

# Arguments:
# $1: Test binary
# $2: Pcaps folder

if [[ $# -ne 2 ]]; then
    echo "Error, two arguments needed, the test binary and the pcaps folder." 
    exit 1
fi

echo "[`basename ${1}`] Checking folder \"`basename ${2}`\""

list_pcaps="$( find ${2} -name "*.pcap" )"
list_pcaps_nr="$( echo "${list_pcaps}" | wc -l )"

echo "${list_pcaps_nr} PCAP traces..."

# For each pcap file in pcaps folder, the pcap is used as an argument of our test.
# Error outputs are collected and counted.
errors_nr=0
for pcap_file in ${list_pcaps} ; do
	echo -n "${1} ${pcap_file}: "
	${1} --ignore-malformed "${pcap_file}" > /dev/null
	ret=$?
	if [ ${ret} -eq 0 ] ; then
		echo "PASS"
	else
		echo "FAIL"
		errors_nr=$(( ${errors_nr} + 1 ))
	fi
done

exit ${errors_nr}

