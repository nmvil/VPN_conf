#!/bin/bash -e

export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt-get -o Acquire::ForceIPv4=true install -y iptables-persistent shadowsocks-libev

ETH0ORSIMILAR=$(ip route get 1.1.1.1 | grep -oP ' dev \K\S+')

iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -F
iptables -t nat -F
iptables -t mangle -F

iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# вот тут поменять!!!
iptables -A INPUT -s 212.192.14.139 -j ACCEPT 

iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s 10.0.0.0/24 -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d 10.0.0.0/24 -j ACCEPT

iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -j MASQUERADE

iptables -A INPUT   -j DROP
iptables -A FORWARD -j DROP

iptables -L
netfilter-persistent save
