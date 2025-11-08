cat >/root/road-warrior.sh <<'EOF'
#!/bin/sh
# Road-Warrior for OpenWrt 24.10.x (x86_64)
# LuCI + luci-app-xray + Xray(TPROXY+DNS) + OpenVPN no-enc + IPv6 + TTL
set -e

say()  { printf "\033[1;32m[RW]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[RW]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[RW]\033[0m %s\n" "$*"; }

# ---------- helpers ----------
cidr2mask() { # "10.99.0.0/24" -> "255.255.255.0"
  bits="${1#*/}"; [ -z "$bits" ] && { echo 255.255.255.0; return; }
  m=0; i=0; while [ $i -lt 32 ]; do [ $i -lt "$bits" ] && m=$((m | (1<<(31-i)))); i=$((i+1)); done
  printf "%d.%d.%d.%d" $(( (m>>24)&255 )) $(( (m>>16)&255 )) $(( (m>>8)&255 )) $(( m&255 ))
}
wan_zone_idx() { uci show firewall 2>/dev/null | sed -n "s/^firewall\.@zone\[\([0-9]\+\)\]\.name='wan'.*/\1/p" | head -n1; }

# ---------- 0) WAN autodetect ----------
WAN_IF="$(ubus call network.interface.wan status 2>/dev/null | sed -n 's/.*\"l3_device\":\"\([^\"]*\)\".*/\1/p')"
[ -z "$WAN_IF" ] && WAN_IF="$(ip route | awk '/default/ {print $5; exit}')"
[ -z "$WAN_IF" ] && WAN_IF="eth0"
has_v4() { ip -4 addr show dev "$WAN_IF" | grep -q 'inet '; }

if ! has_v4; then
  warn "IPv4 по DHCP не получен на $WAN_IF — настраиваю WAN=DHCP..."
  uci -q delete network.wan
  uci -q delete network.wan6
  uci set network.wan='interface'
  uci set network.wan.device="$WAN_IF"
  uci set network.wan.proto='dhcp'
  uci commit network
  /etc/init.d/network restart
  sleep 4
fi

# ---------- 1) distfeeds fix + opkg update ----------
say "Чиню distfeeds (packages-24.10) и обновляю индексы"
cp /etc/opkg/distfeeds.conf /etc/opkg/distfeeds.conf.bak
sed -i 's#https://downloads.openwrt.org/releases/[0-9.]\+/packages/x86_64/#https://downloads.openwrt.org/releases/packages-24.10/x86_64/#g' /etc/opkg/distfeeds.conf
opkg update

# ---------- 2) base packages ----------
say "Устанавливаю пакеты (LuCI, Xray, OpenVPN, nft tproxy, dnsmasq-full, утилиты)"
opkg install -V1 luci luci-ssl ca-bundle curl wget jq ip-full openssl-util
opkg remove dnsmasq 2>/dev/null || true
opkg install dnsmasq-full
opkg install xray-core xray-geodata 2>/dev/null || true
opkg install nftables kmod-nft-tproxy nftables-json
opkg install openvpn-openssl
opkg install nano 2>/dev/null || true

# ---------- 3) luci-app-xray ----------
say "Ставлю luci-app-xray (GUI)"
opkg install luci-app-xray 2>/dev/null || true
if ! opkg list-installed | grep -q '^luci-app-xray'; then
  warn "luci-app-xray нет в фидах — тяну ipk из HTML Releases"
  REL_HTML="$(curl -fsSL -H 'User-Agent: Mozilla/5.0' https://github.com/yichya/luci-app-xray/releases/latest || true)"
  ASSET_PATH="$(printf '%s\n' "$REL_HTML" | sed -n 's#.*href="\(/yichya/luci-app-xray/releases/download/[^"]*luci-app-xray_.*_all\.ipk\)".*#\1#p' | head -n1)"
  if [ -n "$ASSET_PATH" ]; then
    wget -O /tmp/luci-app-xray.ipk "https://github.com${ASSET_PATH}" || true
    opkg install /tmp/luci-app-xray.ipk 2>/dev/null || warn "Не удалось установить luci-app-xray из Releases."
  else
    warn "Не смог извлечь ссылку на ipk из HTML Releases. Можно поставить вручную: LuCI → System → Software."
  fi
fi

# ---------- 4) LuCI enable ----------
/etc/init.d/uhttpd enable
/etc/init.d/uhttpd start

# ---------- 5) Xray minimal (TPROXY+DNS) ----------
say "Пишу /etc/xray/config.json (TPROXY:12345 + dns-out)"
mkdir -p /etc/xray /var/log/xray
cat >/etc/xray/config.json <<'JSON'
{
  "log": { "loglevel": "info", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log" },
  "inbounds": [{
    "tag": "tproxy-in",
    "protocol": "dokodemo-door",
    "port": 12345,
    "settings": { "network": "tcp,udp", "followRedirect": true },
    "streamSettings": { "sockopt": { "tproxy": "tproxy" } }
  }],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "dns-out", "protocol": "dns", "settings": { "address": "8.8.8.8" } }
  ],
  "dns": { "servers": [ "8.8.8.8", "1.1.1.1", "https+local://dns.cloudflare.com/dns-query" ] },
  "routing": { "domainStrategy": "IPIfNonMatch",
    "rules": [{ "type": "field", "inboundTag": ["tproxy-in"], "port": 53, "outboundTag": "dns-out" }]
  }
}
JSON
/etc/init.d/xray enable
/etc/init.d/xray restart

# ---------- 6) Policy routing (fwmark 0x1 -> table 100) + persist ----------
say "Policy routing: fwmark 0x1 -> table 100 (local dev lo)"
ip rule add fwmark 0x1 table 100 2>/dev/null || true
ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
ip -6 rule add fwmark 0x1 table 100 2>/dev/null || true
ip -6 route add local ::/0 dev lo table 100 2>/dev/null || true
mkdir -p /etc/hotplug.d/iface
cat >/etc/hotplug.d/iface/99-xray-tproxy <<'HPL'
[ "$ACTION" = ifup ] || exit 0
case "$INTERFACE" in
  wan|vpn)
    ip rule add fwmark 0x1 table 100 2>/dev/null || true
    ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
    ip -6 rule add fwmark 0x1 table 100 2>/dev/null || true
    ip -6 route add local ::/0 dev lo table 100 2>/dev/null || true
  ;;
esac
HPL
chmod +x /etc/hotplug.d/iface/99-xray-tproxy

# ---------- 7) nft TPROXY (fw4 include; IPv4+IPv6) ----------
say "Вкатываю nft-правила TPROXY (fw4 include на tun0 → :12345)"
mkdir -p /etc/nftables.d
cat >/etc/nftables.d/90-xray-tproxy.nft <<'NFT'
# Этот файл включается ВНУТРЬ "table inet fw4 { ... }"
# поэтому НЕЛЬЗЯ писать "table inet ..." здесь.

set xray_v4_skip { type ipv4_addr; flags interval; elements = {
    127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
    169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4
} }

set xray_v6_skip { type ipv6_addr; flags interval; elements = {
    ::1/128, fc00::/7, fe80::/10, ff00::/8
} }

chain xray_preroute {
  type filter hook prerouting priority mangle; policy accept;

  # DNS (сначала) — IPv4 и IPv6
  iifname "tun0" udp dport 53 tproxy ip  to :12345 meta mark set 0x1
  iifname "tun0" tcp dport 53 tproxy ip  to :12345 meta mark set 0x1
  iifname "tun0" udp dport 53 tproxy ip6 to :12345 meta mark set 0x1
  iifname "tun0" tcp dport 53 tproxy ip6 to :12345 meta mark set 0x1

  # Остальной TCP/UDP
  iifname "tun0" ip  daddr @xray_v4_skip return
  iifname "tun0" meta l4proto { tcp, udp } tproxy ip  to :12345 meta mark set 0x1

  iifname "tun0" ip6 daddr @xray_v6_skip return
  iifname "tun0" meta l4proto { tcp, udp } tproxy ip6 to :12345 meta mark set 0x1
}

chain xray_accept_mark {
  type filter hook input priority mangle; policy accept;
  meta mark 0x1 accept
}
NFT
/etc/init.d/firewall restart

# ---------- 8) OpenVPN (UDP/TUN) no-enc + PKI ----------
say "Ставлю openvpn-easy-rsa (если есть), иначе PKI через OpenSSL (fallback)"
if opkg install openvpn-easy-rsa 2>/dev/null; then
  say "EasyRSA найден — генерю PKI"
  export EASYRSA_BATCH=1
  export EASYRSA_PKI=/etc/easy-rsa/pki
  mkdir -p "$EASYRSA_PKI"
  easyrsa init-pki
  [ -f "$EASYRSA_PKI/ca.crt" ] || easyrsa build-ca nopass
  [ -f "$EASYRSA_PKI/issued/server.crt" ] || easyrsa build-server-full server nopass
  CLIENT="${CLIENT:-client1}"
  [ -f "$EASYRSA_PKI/issued/${CLIENT}.crt" ] || easyrsa build-client-full "${CLIENT}" nopass
  mkdir -p /etc/openvpn/pki
  cp -r "$EASYRSA_PKI"/* /etc/openvpn/pki/
else
  warn "openvpn-easy-rsa недоступен — делаю PKI через OpenSSL (self-signed CA)"
  OVPN_PKI=/etc/openvpn/pki
  mkdir -p "$OVPN_PKI"
  openssl genrsa -out "$OVPN_PKI/ca.key" 4096
  openssl req -x509 -new -nodes -key "$OVPN_PKI/ca.key" -sha256 -days 3650 \
    -subj "/CN=OpenWrt-CA" -out "$OVPN_PKI/ca.crt"
  openssl genrsa -out "$OVPN_PKI/server.key" 4096
  openssl req -new -key "$OVPN_PKI/server.key" -subj "/CN=server" -out "$OVPN_PKI/server.csr"
  openssl x509 -req -in "$OVPN_PKI/server.csr" -CA "$OVPN_PKI/ca.crt" -CAkey "$OVPN_PKI/ca.key" \
    -CAcreateserial -out "$OVPN_PKI/server.crt" -days 3650 -sha256
  CLIENT="${CLIENT:-client1}"
  openssl genrsa -out "$OVPN_PKI/${CLIENT}.key" 4096
  openssl req -new -key "$OVPN_PKI/${CLIENT}.key" -subj "/CN=${CLIENT}" -out "$OVPN_PKI/${CLIENT}.csr"
  openssl x509 -req -in "$OVPN_PKI/${CLIENT}.csr" -CA "$OVPN_PKI/ca.crt" -CAkey "$OVPN_PKI/ca.key" \
    -CAcreateserial -out "$OVPN_PKI/${CLIENT}.crt" -days 3650 -sha256
fi
openvpn --genkey secret /etc/openvpn/pki/tc.key || true

OPORT="${OPORT:-1194}"
VPN4_NET="${VPN4_NET:-10.99.0.0/24}"
VPN6_NET="${VPN6_NET:-fd42:4242:4242:1::/64}"
OVPN4="${VPN4_NET%/*}"
MASK4="$(cidr2mask "$VPN4_NET")"

uci -q delete openvpn.rw
uci set openvpn.rw=openvpn
uci set openvpn.rw.enabled='1'
uci set openvpn.rw.dev='tun0'
uci set openvpn.rw.proto='udp'
uci set openvpn.rw.port="$OPORT"
uci set openvpn.rw.topology='subnet'
uci set openvpn.rw.server="$OVPN4 $MASK4"
uci set openvpn.rw.server_ipv6="$VPN6_NET"
uci set openvpn.rw.keepalive='10 60'
uci set openvpn.rw.persist_key='1'
uci set openvpn.rw.persist_tun='1'
uci set openvpn.rw.explicit_exit_notify='1'
uci add_list openvpn.rw.data_ciphers='none'
uci set openvpn.rw.data_ciphers_fallback='none'
uci set openvpn.rw.auth='none'
uci set openvpn.rw.tls_server='1'
uci set openvpn.rw.ca='/etc/openvpn/pki/ca.crt'
uci set openvpn.rw.cert='/etc/openvpn/pki/issued/server.crt' 2>/dev/null || uci set openvpn.rw.cert='/etc/openvpn/pki/server.crt'
uci set openvpn.rw.key='/etc/openvpn/pki/private/server.key' 2>/dev/null || uci set openvpn.rw.key='/etc/openvpn/pki/server.key'
uci set openvpn.rw.dh='none'
uci add_list openvpn.rw.push='redirect-gateway def1 ipv6'
uci add_list openvpn.rw.push='dhcp-option DNS 10.99.0.1'
uci add_list openvpn.rw.push='dhcp-option DNS6 fd42:4242:4242:1::1'
uci set openvpn.rw.tls_crypt='/etc/openvpn/pki/tc.key'
uci commit openvpn
/etc/init.d/openvpn enable
/etc/init.d/openvpn restart

PUB4="$(ip -4 addr show dev "$WAN_IF" | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)"
CLIENT="${CLIENT:-client1}"
cat >/root/${CLIENT}.ovpn <<EOCLI
client
dev tun
proto udp
remote ${PUB4} ${OPORT}
nobind
persist-key
persist-tun
verb 3
data-ciphers none
data-ciphers-fallback none
auth none
<tls-crypt>
$(cat /etc/openvpn/pki/tc.key 2>/dev/null)
</tls-crypt>
<ca>
$(cat /etc/openvpn/pki/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/pki/issued/${CLIENT}.crt 2>/dev/null || cat /etc/openvpn/pki/${CLIENT}.crt)
</cert>
<key>
$(cat /etc/openvpn/pki/private/${CLIENT}.key 2>/dev/null || cat /etc/openvpn/pki/${CLIENT}.key)
</key>
EOCLI

# ---------- 9) Firewall: vpn zone, NAT4/NAT6, UDP/1194 ----------
say "Настраиваю firewall (зона VPN, NAT v4/v6, порт 1194/udp)"
uci -q delete network.vpn
uci add network interface
uci set network.@interface[-1].ifname='tun0'
uci set network.@interface[-1].proto='none'
uci set network.@interface[-1].auto='1'
uci rename network.@interface[-1]='vpn'
uci commit network

uci -q delete firewall.vpn
uci add firewall zone
uci set firewall.@zone[-1].name='vpn'
uci set firewall.@zone[-1].network='vpn'
uci set firewall.@zone[-1].input='ACCEPT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='ACCEPT'
uci set firewall.@zone[-1].masq='1'
uci set firewall.@zone[-1].mtu_fix='1'

WZ="$(wan_zone_idx)"
if [ -n "$WZ" ]; then
  uci set firewall.@zone[$WZ].masq='1'
  uci set firewall.@zone[$WZ].masq6='1'
else
  warn "Не нашёл WAN-зону в firewall — пропускаю masq/masq6 автоконфиг."
fi

uci add firewall forwarding
uci set firewall.@forwarding[-1].src='vpn'
uci set firewall.@forwarding[-1].dest='wan'

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-OpenVPN'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].dest_port="$OPORT"
uci set firewall.@rule[-1].target='ACCEPT'

uci commit firewall
/etc/init.d/firewall restart
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

# ---------- 10) TTL interactive (IPv4+IPv6) ----------
say "TTL-фикс: выбери режим"
echo " 1) Не менять TTL"
echo " 2) Компенсировать +1 (ttl=ttl+1; hoplimit=+1)"
echo " 3) Зафиксировать конкретный TTL (по умолчанию 127)"
printf "Выбор [1/2/3, по умолчанию 3]: "
read TTLMODE
[ -z "$TTLMODE" ] && TTLMODE=3

TTL_RULE=""
case "$TTLMODE" in
  1) say "TTL не меняем";;
  2) TTL_RULE='ip ttl set ip ttl + 1; ip6 hoplimit set ip6 hoplimit + 1';;
  3) printf "Укажи TTL (Enter = 127): "; read TTLV; [ -z "$TTLV" ] && TTLV=127
     TTL_RULE="ip ttl set ${TTLV}; ip6 hoplimit set ${TTLV}";;
  *) TTL_RULE="ip ttl set 127; ip6 hoplimit set 127";;
esac

if [ -n "$TTL_RULE" ]; then
  say "Применяю TTL/HopLimit на исходящем (${WAN_IF})"
  mkdir -p /etc/nftables.d
  cat >/etc/nftables.d/95-ttlfix.nft <<NFT2
# Вставляется внутрь table inet fw4
chain xrl_ttl_post {
  type route hook postrouting priority mangle; policy accept;
  oifname "${WAN_IF}" ${TTL_RULE}
}
NFT2
  /etc/init.d/firewall restart
fi

# ---------- 11) Summary ----------
say "ГОТОВО!"
IP4="$(ip -4 addr show dev "$WAN_IF" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
IP6="$(ip -6 addr show dev "$WAN_IF" scope global | awk '/inet6 /{print $2}' | cut -d/ -f1 | head -n1)"
echo "LuCI (HTTPS): https://${IP4}"
[ -n "$IP6" ] && echo "LuCI (IPv6): https://[${IP6}]/"
echo "Xray GUI: LuCI → Services → Xray → добавь свой прокси (Node) и включи Transparent Proxy (TCP+UDP)"
echo "OpenVPN клиентский профиль: /root/${CLIENT}.ovpn  (используй OpenVPN GUI 2.5/2.6; Connect v3 не поддерживает no-enc)"
echo "Логи: Xray /var/log/xray/*.log | nft: 'nft list ruleset' | OpenVPN: 'logread -e openvpn'"
EOF

chmod +x /root/road-warrior.sh
/root/road-warrior.sh
