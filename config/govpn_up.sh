#!/bin/sh
tunctl -t tap10
ip addr add 172.19.0.1/24 dev tap10
ip link set up dev tap10
iptables -t nat -A POSTROUTING -s 172.19.0.0/24 -o eth0 -j MASQUERADE
exit 0
