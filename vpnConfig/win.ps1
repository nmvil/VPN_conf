$Response = Invoke-WebRequest -UseBasicParsing -Uri https://valid-isrgrootx1.letsencrypt.org
# ^ this line fixes a certificate lazy-loading bug: see https://github.com/jawj/IKEv2-setup/issues/126

Install-Module -Name VPNCredentialsHelper

Add-VpnConnection -Name "nmvil VPN" `
  -ServerAddress "101034.ip-ns.net" `
  -TunnelType IKEv2 `
  -EncryptionLevel Maximum `
  -AuthenticationMethod EAP `
  -RememberCredential

Set-VpnConnectionIPsecConfiguration -ConnectionName "nmvil VPN" `
  -AuthenticationTransformConstants GCMAES256 `
  -CipherTransformConstants GCMAES256 `
  -EncryptionMethod GCMAES256 `
  -IntegrityCheckMethod SHA384 `
  -DHGroup ECP384 `
  -PfsGroup ECP384 `
  -Force

Set-VpnConnectionUsernamePassword -connectionname $name `
  -username newLogin `
  -password newPass `

