# Smallest base image
FROM alpine:3.4

MAINTAINER Silas Xie <silas@sky-city.me>

RUN apk add --update bash iptables iproute2

VOLUME ["/etc/govpn"]

EXPOSE 1194/udp

ADD ./ /usr/local/govpn
ADD ./config/ /etc/govpn

RUN   ln -s /usr/local/govpn/govpn-client  /usr/local/bin/govpn-client \
      && ln -s /usr/local/govpn/govpn-server  /usr/local/bin/govpn-server \
      && ln -s /usr/local/govpn/govpn-verifier  /usr/local/bin/govpn-verifier \
      && ln -s /usr/local/govpn/utils/addroute.sh  /usr/local/bin/addroute \
      && ln -s /usr/local/govpn/utils/newclient.sh  /usr/local/bin/newclient

CMD ["govpn-server" ,  "-conf", "/etc/govpn/peers.yaml", "-bind", "0.0.0.0:1194"]

