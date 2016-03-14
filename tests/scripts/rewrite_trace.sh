#!/bin/bash -

## Rewrite trace -- Simply rewrite a given trace with given arguments

# Author:    Henrick Deschamps
# Mail:      henrick.deschamps@toulouse.viveris.fr
# Date:      01/2016
# Copyright: 2016, Thalès Alenia Space


# Declare

trace_dir=$(dirname "$1")
in_file=$(basename "$1")

extension="${in_file##*.}"
filename="${in_file%.*}"

cache_file=${filename}.cache
out_file=${filename}.new.${extension}

ip_dest="$4"
ip_src="$2"

mac_dest="$5"
mac_src="$3"

enetdmac=${mac_src},${mac_dest}

endpoints=${ip_dest}:${ip_src}


# Functions

usage () {
    echo "Usage: ${0} <trace.pcap> <IP src> <mac src> <IP dst> <mac dst>"
}


clean_tmp () {
    if [ ! -z "${cache_file}" ]; then
        rm ${cache_file}
    fi
}


rewrite_trace () {
       tcpprep -i ${trace_dir}/${in_file} \
               -o ${cache_file} \
               -p \
    && tcprewrite --cachefile=${cache_file} \
                  --infile=${trace_dir}/${in_file} \
                  --outfile=${out_file} \
                  --enet-dmac=${enetdmac} \
                  --endpoints=${endpoints}
}


# Main

main () {
    if [ "$#" -eq 5 ]; then
        rewrite_trace
        clean_tmp
    else
        echo $#
        usage
    fi
}


main $*
