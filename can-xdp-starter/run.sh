#!/bin/bash

BPF_FILE="can-xdp.bpf.o"
BPF_PROGNAME="xdp_can_drop_id0x123"
DEFAULT_DEV="vcan0"
PIN_FILE="/sys/fs/bpf/can-xdp-starter"

echo "use xdp_unload <dev> to load this program"
echo

if [ $# -eq 0 ] ; then
    # just run with the vcan0 as default
    source ../ebpfloader.sh start_xdp $DEFAULT_DEV
elif [ $# -eq 1 ] ; then
    if [[ "$1" == "help" ]]
    then
        source ../ebpfloader.sh help
    fi
    param_dev=$1
    # start with the parameter
    source ../ebpfloader.sh start_xdp $param_dev
else
    # access all parameters
    source ../ebpfloader.sh
fi
