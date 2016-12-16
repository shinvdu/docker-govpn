#!/bin/sh -x

# A simple script handling default routing for GoVPN,
# inspired by vpnc-script, but much simpler.

# List of parameters passed through environment
# - reason               -- why this script is called:
#                           pre-init, connect, disconnect
# - GOVPN_REMOTE         -- public address of VPN gateway
# - GOVPN_IFACE          -- tap device
# - INTERNAL_IP4_ADDRESS -- e.g. 172.0.0.2/24
# - INTERNAL_IP4_GATEWAY -- e.g. 172.0.0.1


set_up_dev() {
  ip tuntap add dev $GOVPN_IFACE mode tap
}


tear_down_dev() {
  ip tuntap del dev $GOVPN_IFACE mode tap
}


do_connect() {
  local OLDGW=$(ip route show 0/0 | sed 's/^default//')
  ip link set dev $GOVPN_IFACE up
  ip addr add $INTERNAL_IP4_ADDRESS dev $GOVPN_IFACE
  ip route add $GOVPN_REMOTE $OLDGW
  ip route add 0/1 via $INTERNAL_IP4_GATEWAY dev $GOVPN_IFACE
  ip route add 128/1 via $INTERNAL_IP4_GATEWAY dev $GOVPN_IFACE
}


do_disconnect() {
  ip route del $GOVPN_REMOTE
}


case $reason in
  pre-init)
    set_up_dev
    ;;
  connect)
    do_connect
    ;;
  disconnect)
    do_disconnect
    ;;
esac
