#!/usr/sbin/setkey -f
#
#
# Example ESP Tunnel for VPN.
#
#                                 ========= ESP =========
#                                 |                     |
#          Network-A          Gateway-A             Gateway-B           Network-B
#         192.168.1.0/24 ---- 200.200.200.10 ------ 200.200.200.20 ---- 192.168.2.0/24
#
#         ====== 83xx board A ======                  ===== 83xx board B =====
#         |                        |                  |                      |
#         eth0                  eth1                  eth1                eth0
#       192.168.1.130         200.200.200.10          200.200.200.20      192.168.2.130
#
#
# Board A setup
#
# Flush the SAD and SPD
flush;
spdflush;

# I am gateway A (eth0:192.168.1.130, eth1:200.200.200.10)
#
# Security policies
spdadd 192.168.3.211 192.168.3.212 any -P out ipsec
       esp/tunnel/192.168.3.211-192.168.3.212/require;

spdadd 192.168.3.212 192.168.3.211 any -P in ipsec
       esp/tunnel/192.168.3.212-192.168.3.211/require;


# ESP SAs doing encryption using 192 bit long keys (168 + 24 parity)
# and hmac-sha1 authentication using 160 bit long keys
add 192.168.3.211 192.168.3.212 esp 0x201 -m tunnel
    -E 3des-cbc  0x7aeaca3f87d060a12f4a4487d5a5c3355920fae69a96c831
    -A hmac-sha1 0xe9c43acd5e8d779b6e09c87347852708ab49bdd3;

add 192.168.3.212 192.168.3.211 esp 0x301 -m tunnel
    -E 3des-cbc  0xf6ddb555acfd9d77b03ea3843f2653255afe8eb5573965df
    -A hmac-sha1 0xea6856479330dc9c17b8f6c37e2a895363d83f21;

