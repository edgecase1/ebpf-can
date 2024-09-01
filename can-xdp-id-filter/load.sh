

set -o errexit
set -x

BPF_FILE="can-xdp.bpf.o"
PROGNAME="xdp_filter_can"
DEV="vcan0"
PIN_FILE="/sys/fs/bpf/xdp"

perror()
{
    echo $* >&2
    exit 1
}

check_if()
{
    ip link show dev $DEV
    return $?
}

load()
{
    bpftool prog load $BPF_FILE $PIN_FILE
    bpftool net attach xdp name $PROGNAME dev $DEV
}

unload()
{
    rm $PIN_FILE
    bpftool net detach xdp dev $DEV
}


if [[ $# -eq 0 ]]
then
	check_if || perror "error device $DEV"
	load
	echo "loaded. starting shell"
	bash
	unload
elif [[ $# -eq 1 ]]
then
	case $1 in
		load)
			load
			;;
		unload)
			unload
			;;
		reload)
			unload
			load
			;;
		*)
			echo "error"
			exit 1
			;;
	esac
else
	echo "usage: load/unload"
	exit 1
fi

