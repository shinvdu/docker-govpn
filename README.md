

GoVPN is simple free software virtual private network daemon, aimed to
be reviewable, secure, DPI/censorship-resistant, written on Go.

This is the dockefile for govpn. 

Its size is just 37MB.  small enough?

# How to run it

```
$: docker pull shinvdu/govpn
$: docker run -it --rm --device=/dev/net/tun:/dev/net/tun -p 1194:1194/udp  --cap-add=NET_ADMIN  shinvdu/govpn
```

make sure to use custom setting in VOLUME ["/etc/govpn"], just mount. 

```
$: docker run -it --rm \
   --device=/dev/net/tun:/dev/net/tun \
   -p 1194:1194/udp \
   -v /etc/govpn:/etc/govpn  \
   --cap-add=NET_ADMIN  shinvdu/govpn
```

# How to create your own auth key?

$: docker run -it --rm  shinvdu/govpn newclient Govpn


Type a pass, It generate a auth key for you. it looks like below. 
```
Your client verifier is: $argon2d$m=4096,t=128,p=1$ns8qW3Sru5hq3V35LYioug

Place the following YAML configuration entry on the server's side:

    Silas:
        up: /path/to/up.sh
        iface: or TAP interface name
        verifier: $argon2d$m=4096,t=128,p=1$ns8qW3Sru5hq3V35LYioug$rWRXMDzSaa1IXYMVNRM4lPlJ929fkbjhorudL6iRc9I

```

get the verifier, and replace the default one in config/peers.yaml. This is the only step you need to do. 


# How to use client to connect?

example

1. create the network interface:
```
tunctl -t tap14
ip addr add 172.19.0.2/24 dev tap14
ip link set up dev tap14
```

2. create a file hold the pass
```$: echo 'govpn' > /usr/local/src/govpn-5.7/key.txt```

govpn is is pass I just type. 

3. connect. 

```
$: sudo ./govpn-client \
   -verifier  '$argon2d$m=4096,t=128,p=1$B4GsJkH/T+BG0/iOUkkt/w$GOEZuuAuucwIIX8zKUzYPeVdQxJpudO3jB1rv1rjztk'  \
  -iface [tap14]  \
  -remote [public ip]:1194 \
  -key  /usr/local/src/govpn-5.7/key.txt
```

4. check connect status
**client side log output:**

```2016/12/16 08:03:30.342891 udp.go:89: Handshake completed```

**service side log output:**

```
2016/12/16 08:21:56.840962 udp.go:99: Peer handshake finished: 172.17.42.1:38760 B4GsJkH/T+BG0/iOUkkt/w
2016/12/16 08:21:56.846214 udp.go:166: Peer created: B4GsJkH/T+BG0/iOUkkt/w
```

**ping to check package alive**

```
➜  ~ ping 172.19.0.1                                                                                                                                                                                            
PING 172.19.0.1 (172.19.0.1) 56(84) bytes of data.
64 bytes from 172.19.0.1: icmp_seq=9 ttl=64 time=1.10 ms
64 bytes from 172.19.0.1: icmp_seq=10 ttl=64 time=0.711 ms
64 bytes from 172.19.0.1: icmp_seq=11 ttl=64 time=0.679 ms
64 bytes from 172.19.0.1: icmp_seq=12 ttl=64 time=0.665 ms
```

## Setup host routing

**After startup**

```
sudo ip route add  0.0.0.0/1 via 172.19.0.1 dev tap14 
sudo ip route add  [public ip]  via  192.168.1.1 dev eth0
```

**After shutdown**

```
sudo ip route delete  0.0.0.0/1 via 172.19.0.1 dev tap14 
sudo ip route delete  [public ip]  via  192.168.1.1  dev eth0
```
