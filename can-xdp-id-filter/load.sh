#!/bin/bash

set -o errexit

BPF_FILE="can-xdp-filter.bpf.o"
PROGNAME="xdp_filter_can"
#DEFAULT_DEV="vcan0"
PIN_FILE="/sys/fs/bpf/xdp"

perror()
{
    echo $* >&2
    exit 1
}

check_if()
{
    local dev=$1
    if [[ $dev == "" ]] ; then
        return 1
    fi
    ip link show dev $dev 1>/dev/null 2>/dev/null
    return $?
}

check_if_container()
{
    local pid=$1
    local dev=$2
    if [ -z $pid ] ; then
	echo "pid is not an number" >&2
        return 1
    fi
    if [[ $dev == "" ]] ; then
        return 1
    fi
    ps $pid 1>/dev/null 2>/dev/null || perror "process $pid not found"

    nsenter -t $pid -n ip link show dev $dev
    return $?
}

load()
{
    local dev=$1
    check_if $dev || perror "interface $dev not found"

    bpftool prog load $BPF_FILE $PIN_FILE
    bpftool net attach xdp name $PROGNAME dev $dev
}

load_container()
{
    local pid=$1
    local dev=$2
    ps $pid || perror "process $pid not found"
    check_if_container $pid $dev || perror "interface not found"

    bpftool prog load $BPF_FILE $PIN_FILE-$pid || perror "cannot load eBPF program"
    nsenter -t $pid -n bpftool net attach xdp name $PROGNAME dev $dev || perror "cannot attach eBPF program"
}

unload()
{
    local dev=$1
    check_if $dev || perror "interface $dev not found"

    if [ -f $PIN_FILE ] ; then
        rm $PIN_FILE
    fi
    bpftool net detach xdp dev $dev
}

unload_container()
{
    local pid=$1
    local dev=$2
    ps $pid || perror "process $pid not found"
    check_if_container $pid $dev

    rm $PIN_FILE-$pid 
    if [ -f $PIN_FILE-$pid ] ; then
        rm $PIN_FILE-$pid
    fi
    nsenter -t $pid -n bpftool net detach xdp dev $dev
}

clean()
{
    if [ -f $PIN_FILE ] ;
    then
        rm $PIN_FILE
    fi
}

shell()
{
    local dev=$1
    echo "eBPF program has been loaded and attached to device $dev (XDP)."
    echo "After this promt is closed the eBPF program is detached and unloaded."
    echo "Press ENTER or CTRL-D to close this promt."
    read
}

signal_handler()
{
    echo "interrupted! Cleaning up ..."
    unload $dev
    #ip link set $dev xdpgeneric off
    exit 1
}

signal_handler_container()
{
    echo "interrupted! Cleaning up ..."
    unload_container $dev $pid
    clean
    exit 1
}

usage()
{
    echo -e "start\tloads the program and drops into a promt; unloads after the prompt is closed."
    echo -e "load\tloads the program and attaches it to the interface."
    echo -e "unload\tunloads the program and detaches from the interface."
    echo
    echo "start/load/unload <dev>"
    echo "start/load_container/unload_container <pid> <dev>"
    echo
}

if [[ $# -eq 0 ]] # default
then
	usage
	exit 1

elif [[ $# -eq 1 ]] # clean
then
	cmd=$1
	case $cmd in
		clean)
			clean
			;;
		*)
			usage
			exit 1
			;;
	esac

elif [[ $# -eq 2 ]] # start vcan0
then
	cmd=$1
	shift 
	dev=$1
	case $cmd in
		load)
			echo "loading can-xdp-fw and attaching it to $dev"
			load $dev
			;;
		unload)
			echo "unloading can-xdp-fw and attaching it to $dev"
			unload $dev
			;;
		start)
			echo "loading can-xdp-fw and attaching it to $dev"
			trap signal_handler SIGINT
			load $dev
			ip link show vcan0
			echo
			shell $dev
			echo "unloading can-xdp-fw and detaching it to $dev"
			unload $dev
			;;
		clean)
			clean
			;;
		*)
			usage
			exit 1
			;;
	esac

elif [[ $# -eq 3 ]] # start_container can0 31137
then
	cmd=$1
	shift 
	dev=$1
	pid=$2
	case $cmd in
		load_container)
			echo "loading can-xdp-fw and attaching it to $dev in container (pid $pid)."
			load_container $dev $pid
			;;
		unload_container)
			echo "detaching can-xdp-fw from $dev in container (pid $pid)."
			unload_container $dev $pid
			;;
		start_container)
			echo "loading can-xdp-fw and attaching it to $dev in container (pid $pid)."
			load_container $dev $pid
			shell $dev
			echo "detaching can-xdp-fw from $dev in container (pid $pid)."
			unload_container $dev $pid
			;;
		*)
			usage
			exit 1
			;;
	esac
else # unspecified number of parameters
	usage
	exit 1
fi

