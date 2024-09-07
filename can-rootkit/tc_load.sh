#!/bin/bash

set -x

file=root.bpf.o

load()
{
    local dev=$1

    tc qdisc add dev $dev clsact
    tc filter add dev $dev ingress bpf obj $file sec "tc/ingress" direct-action
}

unload()
{
    local dev=$1

    tc filter delete dev $dev ingress
    tc qdisc del dev $dev clsact
}

usage()
{
    echo "<dev>" >&2
}

if [ $# -ne 1 ]
then
    usage
else
    load $1
    bash -r
    unload $1
fi
