#!/bin/bash

set -o errexit

DEFAULT_DEVICE="vcan0"

ip link add dev $DEFAULT_DEVICE type vcan && ip link set dev $DEFAULT_DEVICE up
ip link show dev $DEFAULT_DEVICE

