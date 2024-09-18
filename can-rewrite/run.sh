#!/bin/bash

BPF_FILE="root.bpf.o"
DEFAULT_DEV="vcan0"

echo "use load_tc <dev> to load this program"
echo

if [ $# -eq 0 ] ; then
    # just run with the vcan0 as default
    source ../ebpfloader.sh start_tc $DEFAULT_DEV
elif [ $# -eq 1 ] ; then
    param_dev=$1
    # start with the parameter
    source ../ebpfloader.sh start_tc $param_dev
else
    # access all parameters
    source ../ebpfloader.sh
fi
