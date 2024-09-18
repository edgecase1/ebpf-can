#!/bin/bash

BPF_FILE="can-xdp-filter.bpf.o"
BPF_PROGNAME="xdp_filter_can"
DEFAULT_DEV="vcan0"
PIN_FILE="/sys/fs/bpf/can-xdp-filter"

echo "use xdp_unload <dev> to load this program"
echo

if [ $# -eq 0 ] ; then
    # just run with the vcan0 as default
    source ../ebpfloader.sh xdp_start $DEFAULT_DEV
elif [ $# -eq 1 ] ; then
    if [[ "$1" == "help" ]]
    then
        source ../ebpfloader.sh help
    fi
    param_dev=$1
    # start with the parameter
    source ../ebpfloader.sh xdp_start $param_dev
else
    # access all parameters
    source ../ebpfloader.sh
fi
