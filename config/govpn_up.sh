#!/bin/sh
tunctl -t tap10
ip addr add 172.19.0.1/24 dev tap10
ip link set up dev tap10
exit 0
