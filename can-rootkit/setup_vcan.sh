#!/bin/bash

set -x 
set -o errexit

ip link add dev vcan0 type vcan
ip link set dev vcan0 up

