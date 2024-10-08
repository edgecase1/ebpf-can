#!/bin/bash

BPF_FILE="lengthlimit.bpf.o"
DEFAULT_DEV="vcan0"

echo "use load_tc <dev> to load this program"
echo

if [ $# -eq 0 ] ; then
    # just run with the vcan0 as default
    source ../ebpfloader.sh start_tc $DEFAULT_DEV
elif [ $# -eq 1 ] ; then
    cmd=$1
    if [[ "$cmd" == "clean" ]] ; then
	source ../ebpfloader.sh tc_clean $DEFAULT_DEV
	exit 0
    else
        param_dev=$1
        # start with the parameter
        source ../ebpfloader.sh start_tc $param_dev
    fi
else
    # access all parameters
    source ../ebpfloader.sh
fi
