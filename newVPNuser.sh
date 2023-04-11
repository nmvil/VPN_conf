#!/bin/bash -e
read -r -p "Username: " VPNUSER
NEWPASS=$(head -c 1024 /dev/urandom | LC_ALL=C tr -dc '[0-9a-zA-Z!#$^_*:|?.%;@=,()+\-]' | head -c 50)
mkdir $VPNUSER

sed -r \
-e "11s/NewLogin/$VPNUSER/" \
-e "13s/NewPass/$NEWPASS/" \
./vpnConfig/orig.mobileconfig > $VPNUSER/$VPNUSER.mobileconfig
sed -r \
-e "23s/NewLogin/$VPNUSER/" \
-e "24s/NewPass/$NEWPASS/" \
./vpnConfig/orig.ps1 > $VPNUSER/$VPNUSER.ps1

echo "$VPNUSER : EAP \"$NEWPASS\"" >> /etc/ipsec.secrets
ipsec restart 1>/dev/null
echo
echo "F6 to detach"
echo "python3 -m http.server -d $VPNUSER 8228"
echo "newipaddress:8228/$VPNUSER.mobileconfig"
