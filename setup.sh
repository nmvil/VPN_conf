#!/bin/bash -e

function exit_badly {
  echo "$1"
  exit 1
}

UBUNTUVERSION=$(lsb_release -rs)
[[ "${UBUNTUVERSION}" == "18.04" ]] \
  || [[ "${UBUNTUVERSION}" == "20.04" ]] \
  || [[ "${UBUNTUVERSION}" == "22.04" ]] \
  || exit_badly "This script is for Ubuntu 18.04/20.04/22.04 only: aborting (if you know what you're doing, try deleting this check)"

[[ $(id -u) -eq 0 ]] || exit_badly "Please run this script as root (e.g. sudo ./path/to/this/script)"


echo "--- Adding repositories and installing utilities ---"
echo

export DEBIAN_FRONTEND=noninteractive

apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
add-apt-repository -y universe
add-apt-repository -y restricted
add-apt-repository -y multiverse

apt-get -o Acquire::ForceIPv4=true install -y moreutils dnsutils


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

# read -r -p "VPN username: " VPNUSERNAME
# while true; do
#   read -r -s -p "VPN password (no quotes, please): " VPNPASSWORD
#   echo
#   read -r -s -p "Confirm VPN password: " VPNPASSWORD2
#   echo
#   [[ "${VPNPASSWORD}" = "${VPNPASSWORD2}" ]] && break
#   echo "Passwords didn't match -- please try again"
# done

echo '
Public DNS servers include:

176.103.130.130,176.103.130.131  AdGuard               https://adguard.com/en/adguard-dns/overview.html
176.103.130.132,176.103.130.134  AdGuard Family        https://adguard.com/en/adguard-dns/overview.html
1.1.1.1,1.0.0.1                  Cloudflare/APNIC      https://1.1.1.1
84.200.69.80,84.200.70.40        DNS.WATCH             https://dns.watch
8.8.8.8,8.8.4.4                  Google                https://developers.google.com/speed/public-dns/
208.67.222.222,208.67.220.220    OpenDNS               https://www.opendns.com
208.67.222.123,208.67.220.123    OpenDNS FamilyShield  https://www.opendns.com
9.9.9.9,149.112.112.112          Quad9                 https://quad9.net
77.88.8.8,77.88.8.1              Yandex                https://dns.yandex.com
77.88.8.88,77.88.8.2             Yandex Safe           https://dns.yandex.com
77.88.8.7,77.88.8.3              Yandex Family         https://dns.yandex.com
'

read -r -p "DNS servers for VPN users (default: 1.1.1.1,1.0.0.1): " VPNDNS
VPNDNS=${VPNDNS:-'1.1.1.1,1.0.0.1'}


echo
echo "--- Configuration: general server settings ---"
echo

read -r -p "Timezone (default: Europe/London): " TZONE
TZONE=${TZONE:-'Europe/London'}

read -r -p "Email address for sysadmin (e.g. j.bloggs@example.com): " EMAILADDR

# read -r -p "Desired SSH log-in port (default: 22): " SSHPORT
SSHPORT=22

# read -r -p "New SSH log-in user name: " LOGINUSERNAME

# CERTLOGIN="n"
# if [[ -s /root/.ssh/authorized_keys ]]; then
#   while true; do
#     read -r -p "Copy /root/.ssh/authorized_keys to new user and disable SSH password log-in [Y/n]? " CERTLOGIN
#     [[ ${CERTLOGIN,,} =~ ^(y(es)?)?$ ]] && CERTLOGIN=y
#     [[ ${CERTLOGIN,,} =~ ^no?$ ]] && CERTLOGIN=n
#     [[ $CERTLOGIN =~ ^(y|n)$ ]] && break
#   done
# fi

# while true; do
#   [[ ${CERTLOGIN} = "y" ]] && read -r -s -p "New SSH user's password (e.g. for sudo): " LOGINPASSWORD
#   [[ ${CERTLOGIN} != "y" ]] && read -r -s -p "New SSH user's log-in password (must be REALLY STRONG): " LOGINPASSWORD
#   echo
#   read -r -s -p "Confirm new SSH user's password: " LOGINPASSWORD2
#   echo
#   [[ "${LOGINPASSWORD}" = "${LOGINPASSWORD2}" ]] && break
#   echo "Passwords didn't match -- please try again"
# done

VPNIPPOOL="10.101.0.0/16"


echo
echo "--- Upgrading and installing packages ---"
echo

apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt autoremove -y

debconf-set-selections <<< "postfix postfix/mailname string ${VPNHOST}"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

apt-get -o Acquire::ForceIPv4=true install -y \
  language-pack-en iptables-persistent postfix mutt unattended-upgrades certbot uuid-runtime \
  strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins

# in 22.04 libcharon-standard-plugins is replaced with libcharon-extauth-plugins
apt-get -o Acquire::ForceIPv4=true install -y libcharon-standard-plugins \
  || apt-get -o Acquire::ForceIPv4=true install -y libcharon-extauth-plugins

echo
echo "--- Configuring firewall ---"
echo

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


echo
echo "--- Configuring RSA certificates ---"
echo

mkdir -p /etc/letsencrypt

echo 'rsa-key-size = 4096
pre-hook = /sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
post-hook = /sbin/iptables -D INPUT -p tcp --dport 80 -j ACCEPT
renew-hook = /usr/sbin/ipsec reload && /usr/sbin/ipsec secrets
' > /etc/letsencrypt/cli.ini

certbot certonly --non-interactive --agree-tos --standalone --preferred-challenges http --email "${EMAILADDR}" -d "${VPNHOST}"

ln -f -s "/etc/letsencrypt/live/${VPNHOST}/cert.pem"    /etc/ipsec.d/certs/cert.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/privkey.pem" /etc/ipsec.d/private/privkey.pem
ln -f -s "/etc/letsencrypt/live/${VPNHOST}/chain.pem"   /etc/ipsec.d/cacerts/chain.pem

grep -Fq 'nmvil VPN' /etc/apparmor.d/local/usr.lib.ipsec.charon || echo "
# nmvil VPN
/etc/letsencrypt/archive/${VPNHOST}/* r,
" >> /etc/apparmor.d/local/usr.lib.ipsec.charon

aa-status --enabled && invoke-rc.d apparmor reload


echo
echo "--- Configuring VPN ---"
echo

# ip_forward is for VPN
# ip_no_pmtu_disc is for UDP fragmentation
# others are for security

grep -Fq 'nmvil VPN' /etc/sysctl.conf || echo "
# nmvil VPN
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.${ETH0ORSIMILAR}.disable_ipv6 = 1
" >> /etc/sysctl.conf

sysctl -p


echo "config setup
  strictcrlpolicy=yes
  uniqueids=never

conn roadwarrior
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes

  # https://docs.strongswan.org/docs/5.9/config/IKEv2CipherSuites.html#_commercial_national_security_algorithm_suite
  ike=aes256gcm16-prfsha384-ecp384!
  esp=aes256gcm16-ecp384!

  dpdaction=clear
  dpddelay=900s
  rekey=no
  left=%any
  leftid=@${VPNHOST}
  leftcert=cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightdns=${VPNDNS}
  rightsourceip=${VPNIPPOOL}
  rightsendcert=never
" > /etc/ipsec.conf

echo "${VPNHOST} : RSA \"privkey.pem\"" > /etc/ipsec.secrets

ipsec restart


echo
echo "--- User ---"
echo

# user + SSH

# id -u "${LOGINUSERNAME}" &>/dev/null || adduser --disabled-password --gecos "" "${LOGINUSERNAME}"
# echo "${LOGINUSERNAME}:${LOGINPASSWORD}" | chpasswd
# adduser "${LOGINUSERNAME}" sudo

# sed -r \
# -e "s/^#?Port 22$/Port ${SSHPORT}/" \
# -e 's/^#?LoginGraceTime (120|2m)$/LoginGraceTime 30/' \
# -e 's/^#?X11Forwarding yes$/X11Forwarding no/' \
# -e 's/^#?UsePAM yes$/UsePAM no/' \
# -i.original /etc/ssh/sshd_config

# if [[ $CERTLOGIN = "y" ]]; then
#   mkdir -p "/home/${LOGINUSERNAME}/.ssh"
#   chown "${LOGINUSERNAME}" "/home/${LOGINUSERNAME}/.ssh"
#   chmod 700 "/home/${LOGINUSERNAME}/.ssh"

  # cp "/root/.ssh/authorized_keys" "/home/${LOGINUSERNAME}/.ssh/authorized_keys"
  # chown "${LOGINUSERNAME}" "/home/${LOGINUSERNAME}/.ssh/authorized_keys"
  # chmod 600 "/home/${LOGINUSERNAME}/.ssh/authorized_keys"


# service ssh restart


echo
echo "--- Timezone, mail, unattended upgrades ---"
echo

timedatectl set-timezone "${TZONE}"
/usr/sbin/update-locale LANG=en_GB.UTF-8


sed -r \
-e "s/^myhostname =.*$/myhostname = ${VPNHOST}/" \
-e 's/^inet_interfaces =.*$/inet_interfaces = loopback-only/' \
-i.original /etc/postfix/main.cf

grep -Fq 'nmvil VPN' /etc/aliases || echo "
# nmvil VPN
root: ${EMAILADDR}
${LOGINUSERNAME}: ${EMAILADDR}
" >> /etc/aliases

newaliases
service postfix restart


sed -r \
-e 's|^//Unattended-Upgrade::MinimalSteps "true";$|Unattended-Upgrade::MinimalSteps "true";|' \
-e 's|^//Unattended-Upgrade::Mail "root";$|Unattended-Upgrade::Mail "root";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot "false";$|Unattended-Upgrade::Automatic-Reboot "true";|' \
-e 's|^//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot-Time "02:00";$|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' \
-i /etc/apt/apt.conf.d/50unattended-upgrades

echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
' > /etc/apt/apt.conf.d/10periodic

service unattended-upgrades restart

mkdir vpnConfig

UUID=$(uuidgen)
# orig.mobileconfig
cat << EOF > ./vpnConfig/orig.mobileconfig
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthName</key>
        <string>NewLogin</string>
        <key>AuthPassword</key>
        <string>NewPass</string>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>ExtendedAuthEnabled</key>
        <true/>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>OnDemandEnabled</key>
        <integer>0</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
            <key>Action</key>
            <string>Connect</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>${VPNHOST}</string>
        <key>RemoteIdentifier</key>
        <string>${VPNHOST}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.${UUID}</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>${UUID}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>${VPNNAME}</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>${VPNNAME}</string>
  <key>PayloadIdentifier</key>
  <string>mbpnmvi.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>

EOF


cat << EOF > ./vpnConfig/orig.ps1
\$Response = Invoke-WebRequest -UseBasicParsing -Uri https://valid-isrgrootx1.letsencrypt.org

Install-Module -Name VPNCredentialsHelper

Add-VpnConnection -Name ${VPNNAME} \`
  -ServerAddress "${VPNHOST}" \`
  -TunnelType IKEv2 \`
  -EncryptionLevel Maximum \`
  -AuthenticationMethod EAP \`
  -RememberCredential

Set-VpnConnectionIPsecConfiguration -ConnectionName ${VPNNAME} \`
  -AuthenticationTransformConstants GCMAES256 \`
  -CipherTransformConstants GCMAES256 \`
  -EncryptionMethod GCMAES256 \`
  -IntegrityCheckMethod SHA384 \`
  -DHGroup ECP384 \`
  -PfsGroup ECP384 \`
  -Force

Set-VpnConnectionUsernamePassword -connectionname ${VPNNAME} \`
  -username NewLogin \`
  -password NewPass

EOF


cat << EOF > ./newVPNuser.sh
#!/bin/bash -e
read -r -p "Username: " VPNUSER
NEWPASS=\$(head -c 1024 /dev/urandom | LC_ALL=C tr -dc '[0-9a-zA-Z!#$%&()*+,./:;]' | head -c 50)
mkdir \$VPNUSER

sed -r \
-e "11s/NewLogin/\$VPNUSER/" \
-e "13s/NewPass/\$NEWPASS/" \
./vpnConfig/orig.mobileconfig > \$VPNUSER/\$VPNUSER.mobileconfig
sed -r \
-e "23s/NewLogin/\$VPNUSER/" \
-e "24s/NewPass/\$NEWPASS/" \
./vpnConfig/orig.ps1 > \$VPNUSER/\$VPNUSER.ps1

echo "\$VPNUSER : EAP \"\$NEWPASS\"" >> /etc/ipsec.secrets
ipsec restart 1>/dev/null
echo
echo "F6 to detach"
echo "python3 -m http.server -d \$VPNUSER 8228"
echo "${IP}:8228/\$VPNUSER.mobileconfig"

EOF


