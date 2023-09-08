apt-get -o Acquire::ForceIPv4=true update
add-apt-repository -y universe
add-apt-repository -y restricted
add-apt-repository -y multiverse
apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt autoremove -y
apt-get -o Acquire::ForceIPv4=true install -y language-pack-en iptables-persistent postfix mutt unattended-upgrades certbot uuid-runtime
apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
apt-get -o Acquire::ForceIPv4=true install -y moreutils dnsutils

# синхронизация времени
# sed -r -e "s/#NTP=/NTP=0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org/" /etc/systemd/timesyncd.conf > /etc/systemd/timesyncd.conf
# systemctl restart systemd-timesyncd
# systemctl status systemd-timesyncd

echo
echo "--- Configuration: VPN settings ---"
echo

ETH0ORSIMILAR=$(ip route get 1.1.1.1 | grep -oP ' dev \K\S+')
IP=$(dig -4 +short myip.opendns.com @resolver1.opendns.com)

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
echo "--- Configuring RSA certificates ---"
echo

mkdir -p /etc/letsencrypt

echo 'rsa-key-size = 4096
pre-hook = /sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
post-hook = /sbin/iptables -D INPUT -p tcp --dport 80 -j ACCEPT
renew-hook = systemctl restart ocserv
' > /etc/letsencrypt/cli.ini

certbot certonly --non-interactive --agree-tos --standalone --preferred-challenges http --email "${EMAILADDR}" -d "${VPNHOST}"

# firewall
# https://www.strongswan.org/docs/LinuxKongress2009-strongswan.pdf
# https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling
# https://www.zeitgeist.se/2013/11/26/mtu-woes-in-ipsec-tunnels-how-to-fix/

iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -F
iptables -t nat -F
iptables -t mangle -F

# INPUT

# accept anything already accepted
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# accept anything on the loopback interface
iptables -A INPUT -i lo -j ACCEPT

# drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# rate-limit repeated new requests from same IP to any ports
iptables -I INPUT -i "${ETH0ORSIMILAR}" -m state --state NEW -m recent --set
iptables -I INPUT -i "${ETH0ORSIMILAR}" -m state --state NEW -m recent --update --seconds 300 --hitcount 60 -j DROP

# accept (non-standard) SSH
iptables -A INPUT -p tcp --dport "${SSHPORT}" -j ACCEPT
# using for web-server
iptables -A INPUT -p tcp --dport 8228 -j ACCEPT


# VPN

# accept IPSec/NAT-T for VPN (ESP not needed with forceencaps, as ESP goes inside UDP)
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# forward VPN traffic anywhere
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s "${VPNIPPOOL}" -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d "${VPNIPPOOL}" -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc.
iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s "${VPNIPPOOL}" -o "${ETH0ORSIMILAR}" -j MASQUERADE


# fall through to drop any other input and forward traffic

iptables -A INPUT   -j DROP
iptables -A FORWARD -j DROP

iptables -L

netfilter-persistent save

# sed -r -e "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/" /etc/sysctl.conf > /etc/sysctl.conf
# sysctl -p

apt-get -o Acquire::ForceIPv4=true install -y ocserv
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
isolate-workers = true
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
ipv4-network = 10.0.0.0/24
tunnel-all-dns = true
dns = 1.1.1.1
dns = 1.0.0.1
route = default

EOF


