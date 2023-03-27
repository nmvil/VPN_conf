#!/bin/bash -e
read -r -p "Username: " VPNUSER
NEWPASS=$(head -c 1024 /dev/urandom | LC_ALL=C tr -dc '[0-9a-zA-Z!#$^_*:|?.%;@=,()+\-]' | head -c 50)
mkdir $VPNUSER
sed -r \
-e "11s/NewLogin/$VPNUSER/" \
-e "13s/NewPass/$NEWPASS/" \
/root/VPN/vpnConfig/orig.mobileconfig > $VPNUSER/$VPNUSER.mobileconfig
echo "$VPNUSER : EAP \"$NEWPASS\"" >> /etc/ipsec.secrets
ipsec restart 1>/dev/null
echo
echo "F6 to detach"
echo "python3 -m http.server -d $VPNUSER 8228"
echo "178.33.208.194:8228/$VPNUSER.mobileconfig"
