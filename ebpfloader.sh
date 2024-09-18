#!/bin/bash

set -o errexit

#BPF_FILE="can-xdp-filter.bpf.o"
#PROGNAME="xdp_filter_can" # now called BPF_PROGNAME
#PIN_FILE="/sys/fs/bpf/xdp"

#DEFAULT_DEV="vcan0"

perror()
{
    echo $* >&2
    exit 1
}

log_info()
{
    echo "[ ] $*" >&1
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
    local dev=$1
    local pid=$2
    if [ -z $pid ] ; then
	echo "pid is not an number" >&2
        return 1
    fi
    if [[ $dev == "" ]] ; then
        return 1
    fi
    ps $pid 1>/dev/null 2>/dev/null || perror "process $pid not found"

    nsenter -t $pid -n ip link show dev $dev 1>/dev/null 2>/dev/null
    return $?
}

xdp_load()
{
    local dev=$1
    [ -z ${PIN_FILE+x} ] && perror "PIN_FILE not set"
    [ -z ${BPF_PROGNAME+x} ] && perror "BPF_PROGNAME not set"
    check_if $dev || perror "interface $dev not found"
    bpftool prog load $BPF_FILE $PIN_FILE || perror "error loading program '$BPF_PROGNAME' with pinfile '$PIN_FILE'"
    bpftool net attach xdp name $BPF_PROGNAME dev $dev || perror "error attaching to device $dev"
}

xdp_load_container()
{
    local dev=$1
    local pid=$2
    [ -z ${PIN_FILE+x} ] && perror "Pinfile not set"
    ps $pid 1>/dev/null 2>/dev/null || perror "process '$pid' not found"
    check_if_container $dev $pid || perror "interface '$dev' not found in container pid '$pid'"

    bpftool prog load $BPF_FILE $PIN_FILE-$pid || perror "cannot load eBPF program"
    nsenter -t $pid -n bpftool net attach xdp name $BPF_PROGNAME dev $dev || perror "cannot attach eBPF program"
}

xdp_unload()
{
    local dev=$1
    check_if $dev || perror "interface $dev not found"

    if [ -f $PIN_FILE ] ; then
        rm $PIN_FILE
    fi
    bpftool net detach xdp dev $dev
}

xdp_unload_container()
{
    local dev=$1
    local pid=$2
    ps $pid 1>/dev/null 2>/dev/null || perror "process $pid not found"
    check_if_container $dev $pid

    if [ -f $PIN_FILE-$pid ] ; then
        rm $PIN_FILE-$pid
    fi
    nsenter -t $pid -n bpftool net detach xdp dev $dev
}

tc_load()
{
    local dev=$1
    check_if $dev

    tc qdisc add dev $dev clsact || perror "error creating clsact in TC"
    tc filter add dev $dev ingress bpf obj $BPF_FILE sec "tc/ingress" direct-action || perror "error attaching '$BPF_FILE' on device $dev"
}

tc_unload()
{
    local dev=$1

    tc filter delete dev $dev ingress || perror "error deleting filter on device $dev"
    tc qdisc del dev $dev clsact || perror "error deleting clsact on $dev"
}


clean()
{
    if [ -f $PIN_FILE ] ;
    then
	echo "Pinfile '$PIN_FILE' removed." >&2
        rm $PIN_FILE
    fi
    echo "Look for '$PIN_FILE-<pid>' ..."
    echo 
    bpftool prog show name $BPF_PROGNAME
    if [ $? -eq 0 ]
    then
	 echo "try to unload the programs"
    fi
}

shell()
{
    local dev=$1
    echo "------------------------------------------------------------------------"
    echo "eBPF program has been loaded and attached to device $dev."
    echo "After this promt is closed the eBPF program is detached and unloaded."
    echo "Press ENTER or CTRL-D to close this promt."
    echo "------------------------------------------------------------------------"
    read
}

signal_handler_xdp()
{
    echo "interrupted! Cleaning up ..."
    xdp_unload $dev
    #ip link set $dev xdpgeneric off
    exit 1
}

signal_handler_xdp_container()
{
    echo "interrupted! Cleaning up ..."
    xdp_unload_container $dev $pid
    clean
    exit 1
}

usage()
{
    echo -e "xdp_start\tloads the program and drops into a promt; unloads after the prompt is closed."
    echo -e "xdp_load\tloads the program and attaches it to the interface."
    echo -e "xdp_unload\tunloads the program and detaches from the interface."
    echo
    echo -e "tc_unload\t"
    echo -e "tc_load\t"
    echo -e "tc_start\t"
    echo
    echo "start/load/unload <dev>"
    echo "start/load/unload <dev>"
    echo "start/load_container/unload_container <dev> <pid>"
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
		usage)
			usage
			exit 1
			;;
		help)
			usage
			exit 1
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
	[[ "$dev" =~ [:alnum:] ]] || perror "the interface '$dev' looks odd."
	case $cmd in
		xdp_load)
			log_info "loading '$BPF_FILE' and attaching it to $dev (XDP)"
			xdp_load $dev
			ip link show $dev
			;;
		xdp_unload)
			log_info "unloading '$BPF_FILE' and attaching it to $dev (XDP)"
			xdp_unload $dev
			ip link show $dev 
			;;
		xdp_start)
			log_info "loading '$BPF_FILE' and attaching it to $dev (XDP)"
			trap signal_handler_xdp SIGINT
			xdp_load $dev
			ip link show $dev # display device (check for generic xdp(
			echo # newline
			shell $dev
			log_info "unloading '$BPF_FILE' and detaching it to $dev (XDP)"
			xdp_unload $dev
			;;
		xdp_clean)
                        log_info "releasing Pinfile '$PIN_FILE'"
                        [ -f $PIN_FILE ] && rm $PIN_FILE
                        log_info "releasing Pinfile '$PIN_FILE'"
                        bpftool prog show name $BPF_PROGNAME && log_info "the program still exists."
			;;
                tc_load)
			log_info "loading '$BPF_FILE' and attaching it to $dev tc (ingress)"
                        tc_load $dev
			tc filter show dev $dev ingress
                        ;;
                tc_unload)
			log_info "unloading '$BPF_FILE' and detaching it to $dev tc"
                        tc_unload $dev
                        ;;
		tc_start)
			log_info "loading '$BPF_FILE' and attaching it to $dev tc (ingress)"
                        tc_load $dev
			log_info "this is the tc filter output of $dev:"
			tc filter show dev $dev ingress
			shell $dev
			log_info "unloading '$BPF_FILE' and detaching it to $dev tc"
                        tc_unload $dev
			;;
		tc_clean)
			tc_unload $dev
			tc filter show dev $dev ingress
                        bpftool prog show name $BPF_PROGNAME && log_info "the program still exists."
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
	let pid=$2
	# check format
	[[ "$dev" =~ [:alnum:] ]] || perror "the interface '$dev' looks odd."
        #[[ "$pid" =~ [:digit:] ]] || perror "pid '$pid' should be a number!"
	[ $pid -ne 0 ] || perror "pid '$pid' looks odd"
	case $cmd in
		load_container)
			echo "loading '$BPF_FILE' and attaching it to $dev in container (pid $pid)."
			xdp_load_container $dev $pid
			;;
		unload_container)
			echo "detaching '$BPF_FILE' from $dev in container (pid $pid)."
			xdp_unload_container $dev $pid
			;;
		start_container)
			echo "loading '$BPF_FILE' and attaching it to $dev in container (pid $pid)."
			xdp_load_container $dev $pid
			shell $dev
			echo "detaching '$BPF_FILE' from $dev in container (pid $pid)."
			xdp_unload_container $dev $pid
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

