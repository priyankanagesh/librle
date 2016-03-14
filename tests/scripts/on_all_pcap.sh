#!/bin/bash

if [[ $# -lt 2 ]]; then
	echo "NAME"
	echo "	$(basename $0) - Run a test_script against every pcap file from pcap_folder"
	echo "USAGE"
	echo "	$(basename $0) test_script pcap_folder [script_args...]"
	echo "RETURN"
	echo "	The total number of failed tests"
	exit 1
fi

list_pcaps="$( find ${2} -name "*.pcap" )"
list_pcaps_num="$( echo "${list_pcaps}" | wc -l )"

# Error outputs are collected and counted.
errors_sum=0
for pcap_file in ${list_pcaps} ; do
	printf "%-70s" "$(basename $1) $(basename $pcap_file): "
	${1} --ignore-malformed ${@:3} "${pcap_file}" > /dev/null
	ret=$?
	if [ ${ret} -eq 0 ] ; then
		echo '[PASS]'
	else
		echo '[FAIL]'
		errors_sum=$(( ${errors_sum} + 1 ))
	fi
done

exit ${errors_sum}

