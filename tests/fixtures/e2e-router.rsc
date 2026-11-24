# 2026-11-23 12:00:00 by RouterOS 7.20.4
# model = RB5009UG+S+
/system identity
set name=AYNUO-E2E
/ip service
set telnet disabled=no port=23 address=""
set ftp disabled=yes port=21 address=""
set ssh disabled=no port=22 address=10.0.0.0/24
set winbox disabled=no port=8291 address=""
/ip ssh
set strong-crypto=no
/ip upnp
set enabled=yes
/ip dns
set allow-remote-requests=yes servers=1.1.1.1
/snmp
set enabled=yes
/snmp community
add name=public addresses=0.0.0.0/0 write-access=yes
/user
add name=admin group=full address=""
/user settings
set minimum-password-length=0
/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=8291
/ip firewall nat
add chain=dstnat action=dst-nat protocol=tcp dst-port=8291 to-addresses=192.0.2.10
/interface pptp-server server
set enabled=yes
/system logging
add topics=info action=memory
/interface wireless
set wlan1 disabled=no wps-mode=push-button

