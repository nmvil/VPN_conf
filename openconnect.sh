#!/bin/bash -e

export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
add-apt-repository -y universe
add-apt-repository -y restricted
add-apt-repository -y multiverse
apt-get -o Acquire::ForceIPv4=true install -y ocserv ufw certbot dirmngr apt-transport-https gnupg2 ca-certificates lsb-release ubuntu-keyring unzip moreutils dnsutils
apt autoremove -y


# синхронизация времени
# sed -r -e "s/#NTP=/NTP=0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org/" /etc/systemd/timesyncd.conf > /etc/systemd/timesyncd.conf
# systemctl restart systemd-timesyncd
# systemctl status systemd-timesyncd

echo
echo "--- Configuration: VPN settings ---"
echo

ETH0ORSIMILAR=$(ip route get 1.1.1.1 | grep -oP ' dev \K\S+')
IP=$(dig -4 +short myip.opendns.com @resolver1.opendns.com)
VPNIPPOOL="10.0.0.0/24"


echo "Network interface: ${ETH0ORSIMILAR}"
echo "External IP: ${IP}"
echo
echo "** Note: this hostname must already resolve to this machine, to enable Let's Encrypt certificate setup **"
read -r -p "Hostname for VPN: " VPNHOST
if [[ -z $VPNHOST ]]; then
  VPNHOST=$IP.sslip.io
fi

VPNHOSTIP=$(dig -4 +short "${VPNHOST}")
[[ -n "$VPNHOSTIP" ]] || exit_badly "Cannot resolve VPN hostname: aborting"

if [[ "${IP}" != "${VPNHOSTIP}" ]]; then
  echo "Warning: ${VPNHOST} resolves to ${VPNHOSTIP}, not ${IP}"
  echo "Either you're behind NAT, or something is wrong (e.g. hostname points to wrong IP, CloudFlare proxying shenanigans, ...)"
  read -r -p "Press [Return] to continue anyway, or Ctrl-C to abort"
fi

read -r -p "Profile name: " VPNNAME
if [[ -z $VPNNAME ]]; then
  VPNNAME="nmvil VPN"
fi


read -r -p "Email address for sysadmin (e.g. j.bloggs@example.com): " EMAILADDR



echo
echo "--- Configuration: firewall ---"
echo

ufw allow 22/tcp
ufw allow 80,443/tcp
ufw allow 443/udp

sed '/ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT/a \ \
# allow forwarding for trusted network \
-A ufw-before-forward -s 10.0.0.0/24 -j ACCEPT \
-A ufw-before-forward -d 10.0.0.0/24 -j ACCEPT' /etc/ufw/before.rules > /etc/ufw/before.rules

echo "
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s ${VPNIPPOOL} -o ${ETH0ORSIMILAR} -j MASQUERADE

# End each table with the 'COMMIT' line or these rules won't be processed
COMMIT
" >> /etc/ufw/before.rules

ufw enable

echo
echo "--- Configuring RSA certificates ---"
echo

mkdir -p /etc/letsencrypt

echo 'rsa-key-size = 4096
renew-hook = systemctl restart ocserv
' > /etc/letsencrypt/cli.ini

certbot certonly --non-interactive --agree-tos --standalone --preferred-challenges http --email "${EMAILADDR}" -d "${VPNHOST}"

systemctl enable ocserv

cat << EOF > /etc/ocserv/ocserv.conf
auth = "plain[passwd=/etc/ocserv/ocserv.passwd]"
tcp-port = 443
udp-port = 443
run-as-user = nobody
run-as-group = daemon
socket-file = /run/ocserv.socket
server-cert = "/etc/letsencrypt/live/${VPNHOST}/fullchain.pem"
server-key = "/etc/letsencrypt/live/${VPNHOST}/privkey.pem"
max-clients = 64
max-same-clients = 2
compression = true
no-compress-limit = 256
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-RSA:-VERS-ALL:+VERS-TLS1.2:-ARCFOUR-128"
server-stats-reset-time = 604800
keepalive = 300
dpd = 60
mobile-dpd = 300
switch-to-tcp-timeout = 25
try-mtu-discovery = false
cert-user-oid = 0.9.2342.19200300.100.1.1
auth-timeout = 240
idle-timeout = 1200
mobile-idle-timeout = 1800
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 300
ban-points-wrong-password = 3
ban-points-connection = 1
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /run/ocserv.pid
device = vpns
predictable-ips = true
default-domain = ${VPNHOST}
ipv4-network = ${VPNIPPOOL}
tunnel-all-dns = true
dns = 1.1.1.1
dns = 1.0.0.1
route = default

EOF

echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/60-custom.conf
echo "net.core.default_qdisc=fq" >> /etc/sysctl.d/60-custom.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/60-custom.conf
sysctl -p /etc/sysctl.d/60-custom.conf

systemctl restart ocserv


