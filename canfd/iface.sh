#!/bin/bash

iface="vcan0"

ip link add $iface type vcan
ip link set up dev $iface
