#!/bin/bash

# Special static test script.

# Arguments:
# $1: Test binary
# $2: Pcap file
# $3: arguments

if [[ $# -ne 3 ]]; then
    echo "Error, three arguments needed, the test binary, the arguments and the pcaps file." 
    exit 1
fi

echo "[`basename ${1}`] Special test on \"`basename ${2}`\" with argument \"-${3}\""

list_pcaps="$( find ${2} -name "*.pcap" )"
list_pcaps_nr="$( echo "${list_pcaps}" | wc -l )"

echo "${list_pcaps_nr} PCAP traces..."

# For each pcap file in pcaps folder, the pcap is used as an argument of our test.
# Error outputs are collected and counted.
errors_nr=0
for pcap_file in ${list_pcaps} ; do
	echo -n "${1} ${pcap_file}: "
	${1} --ignore-malformed -${3} "${pcap_file}" > /dev/null
	ret=$?
	if [ ${ret} -eq 0 ] ; then
		echo "PASS"
	else
		echo "FAIL"
		errors_nr=$(( ${errors_nr} + 1 ))
	fi
done

exit ${errors_nr}

