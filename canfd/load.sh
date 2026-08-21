#!/bin/bash

set -o errexit

iface="vcan0"

load()
{
    ip link set dev $iface xdp obj xdp_canfd_check.o sec xdp
}

unload()
{
    ip link set dev $iface xdp off
}

catpipe()
{
    cat /sys/kernel/debug/tracing/trace_pipe
}

trap unload INT TERM

echo "loading"
load
echo -n "loaded ... CTRL-C to unload"
catpipe
unload

