cat >/root/road-warrior.sh <<'EOF'
#! /bin/sh
# Road-Warrior for OpenWrt 24.10.x (x86_64)
# LuCI + (опц.) luci-app-passwall + Xray(TPROXY+DNS) + OpenVPN (no-enc) + IPv6 + интерактив TTL

say()  { printf "\033[1;32m[RW]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[RW]\033[0m %s\n" "$*"; }

# ---------- helpers ----------
ask_var() { # ask_var "Вопрос" VAR "дефолт"
  local _q="$1" _name="$2" _def="$3" _val
  printf "%s [%s]: " "$_q" "$_def"
  read -r _val
  eval "$_name=\"${_val:-$_def}\""
}
cidr2mask() {
  bits="${1#*/}"; [ -z "$bits" ] && { echo 255.255.255.0; return; }
  m=0; i=0; while [ $i -lt 32 ]; do [ $i -lt "$bits" ] && m=$((m | (1<<(31-i)))); i=$((i+1)); done
  printf "%d.%d.%d.%d" $(( (m>>24)&255 )) $(( (m>>16)&255 )) $(( (m>>8)&255 )) $(( m&255 ))
}
wan_zone_idx(){ uci show firewall 2>/dev/null | sed -n "s/^firewall\.@zone\[\([0-9]\+\)\]\.name='wan'.*/\1/p" | head -n1; }
has_v4(){ ip -4 addr show dev "$WAN_IF" | grep -q 'inet '; }

# ---------- 0) Приветствие + интерактивные параметры ----------
say "Интерактивный мастер настройки (вводи значение и жми Enter; дефолт — в [] )"

# Автодетект WAN
DET_WAN="$(ubus call network.interface.wan status 2>/dev/null | sed -n 's/.*\"l3_device\":\"\([^\"]*\)\".*/\1/p')"
[ -z "$DET_WAN" ] && DET_WAN="$(ip route | awk '/default/ {print $5; exit}')"
[ -z "$DET_WAN" ] && DET_WAN="eth0"
ask_var "Интерфейс WAN" WAN_IF "$DET_WAN"

ask_var "Порт OpenVPN (UDP)" OPORT "1194"
ask_var "Имя VPN‑клиента (CN)" CLIENT "client1"
ask_var "VPN IPv4‑подсеть" VPN4_NET "10.99.0.0/24"
ask_var "VPN IPv6‑подсеть (ULA /64)" VPN6_NET "fd42:4242:4242:1::/64"

printf "Задать пароль для LuCI/SSH (root)? (Enter=нет / 1=да): "
read -r SETPW
PW_STATUS="не изменён (как сейчас)"
if [ "$SETPW" = "1" ]; then
  printf "Введите НОВЫЙ пароль root: "
  stty -echo 2>/dev/null || true; read -r NEWPW; stty echo 2>/dev/null || true; echo
  if [ -n "$NEWPW" ]; then
    printf "%s\n%s\n" "$NEWPW" "$NEWPW" | passwd root >/dev/null 2>&1 || warn "Не удалось задать пароль."
    PW_STATUS="установлен (только что)"
  fi
fi

printf "Пытаться автоматически поставить luci-app-passwall (GUI для Xray)? [Y/n]: "
read -r AUTOXR; [ -z "$AUTOXR" ] && AUTOXR="Y"

# ---------- 1) distfeeds + пакеты ----------
say "Обновляю списки пакетов и ставлю зависимости"
cp /etc/opkg/distfeeds.conf /etc/opkg/distfeeds.conf.bak 2>/dev/null || true
sed -i 's#https://downloads.openwrt.org/releases/[0-9.]\+/packages/x86_64/#https://downloads.openwrt.org/releases/packages-24.10/x86_64/#g' /etc/opkg/distfeeds.conf
opkg update || true
opkg install -V1 luci luci-ssl ca-bundle curl wget jq ip-full openssl-util luci-compat || true
opkg remove dnsmasq 2>/dev/null || true; opkg install dnsmasq-full || true
opkg install xray-core || true
opkg install v2ray-geoip v2ray-geosite 2>/dev/null || opkg install xray-geodata 2>/dev/null || true
opkg install nftables kmod-nft-tproxy nftables-json || true
opkg install openvpn-openssl kmod-tun || true
opkg install openvpn-easy-rsa 2>/dev/null || true
opkg install nano 2>/dev/null || true

# ---------- 2) WAN bring‑up при необходимости ----------
if ! has_v4; then
  warn "IPv4 на $WAN_IF не получен — настраиваю WAN=DHCP"
  uci -q delete network.wan; uci -q delete network.wan6
  uci set network.wan='interface'; uci set network.wan.device="$WAN_IF"; uci set network.wan.proto='dhcp'
  uci commit network; /etc/init.d/network restart; sleep 4
fi

# ---------- 3) (опц.) установка luci-app-passwall ----------
if [ "$AUTOXR" = "Y" ] || [ "$AUTOXR" = "y" ]; then
  say "Добавляю репозиторий Passwall (x86_64) и ставлю GUI"
  
  # 0. Очищаем старые/битые ссылки (с 'master'), если они есть
  sed -i '/passwall_packages/d' /etc/opkg/custom.conf 2>/dev/null
  sed -i '/passwall_luci/d' /etc/opkg/custom.conf 2>/dev/null

  # 1. Добавляем ПРАВИЛЬНЫЕ фиды (с веткой 'main')
  echo "src/gz passwall_packages https://raw.githubusercontent.com/xiaorouji/openwrt-passwall-packages/main/x86_64/packages" >> /etc/opkg/custom.conf
  echo "src/gz passwall_luci https://raw.githubusercontent.com/xiaorouji/openwrt-passwall-packages/main/x86_64/luci" >> /etc/opkg/custom.conf
  
  # 2. Обновляем и ставим
  opkg update || true
  opkg install luci-app-passwall 2>/dev/null || true

  # 3. Проверка
  if opkg list-installed | grep -q '^luci-app-passwall'; then
    say "luci-app-passwall успешно установлен."
  else
    warn "Автоматическая установка luci-app-passwall не удалась."
    warn "Проверьте /etc/opkg/custom.conf и попробуйте 'opkg install luci-app-passwall' вручную."
  fi
fi

# ---------- 4) Включаем LuCI (HTTPS) ----------
/etc/init.d/uhttpd enable >/dev/null 2>&1
/etc/init.d/uhttpd start  >/dev/null 2>&1

# ---------- 5) Xray: TPROXY + DNS ----------
say "Пишу /etc/xray/config.json (TPROXY:12345 + Xray DNS)"
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
/etc/init.d/xray enable >/dev/null 2>&1
/etc/init.d/xray restart >/dev/null 2>&1

# ---------- 6) Policy routing под TPROXY ----------
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

# ---------- 7) nft TPROXY include (fw4; IPv4+IPv6) ----------
say "Вкатываю nft‑правила TPROXY (prerouting на tun0 → :12345)"
mkdir -p /etc/nftables.d
cat >/etc/nftables.d/90-xray-tproxy.nft <<'NFT'
# Этот файл включается внутрь table inet fw4
set xray_v4_skip { type ipv4_addr; flags interval; elements = {
  127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4
} }
set xray_v6_skip { type ipv6_addr; flags interval; elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 } }

chain xray_preroute {
  type filter hook prerouting priority mangle; policy accept;
  # DNS сначала (UDP/TCP, v4/v6)
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
/etc/init.d/firewall restart >/dev/null 2>&1 || true

# ---------- 8) OpenVPN (UDP/TUN) no‑enc + PKI ----------
say "Готовлю PKI: EasyRSA (если есть) или OpenSSL‑fallback"

if command -v easyrsa >/dev/null 2>&1; then
  EASYRSA_PKI="/etc/easy-rsa/pki"
  EASYRSA_BATCH=1 easyrsa init-pki   >/dev/null 2>&1 || true
  [ -f "$EASYRSA_PKI/ca.crt" ] || EASYRSA_BATCH=1 easyrsa build-ca nopass >/dev/null 2>&1
  [ -f "$EASYRSA_PKI/issued/server.crt" ] || EASYRSA_BATCH=1 easyrsa build-server-full server nopass >/dev/null 2>&1
  [ -f "$EASYRSA_PKI/issued/${CLIENT}.crt" ] || EASYRSA_BATCH=1 easyrsa build-client-full "${CLIENT}" nopass >/dev/null 2>&1
  mkdir -p /etc/openvpn/pki; cp -r "$EASYRSA_PKI/"* /etc/openvpn/pki/ 2>/dev/null || true
else
  OVPN_PKI=/etc/openvpn/pki
  mkdir -p "$OVPN_PKI"
  [ -f "$OVPN_PKI/ca.crt" ] || { \
    openssl genrsa -out "$OVPN_PKI/ca.key" 4096 >/dev/null 2>&1; \
    openssl req -x509 -new -nodes -key "$OVPN_PKI/ca.key" -sha256 -days 3650 -subj "/CN=OpenWrt-CA" -out "$OVPN_PKI/ca.crt" >/dev/null 2>&1; }
  [ -f "$OVPN_PKI/server.crt" ] || { \
    openssl genrsa -out "$OVPN_PKI/server.key" 4096 >/dev/null 2>&1; \
    openssl req -new -key "$OVPN_PKI/server.key" -subj "/CN=server" -out "$OVPN_PKI/server.csr" >/dev/null 2>&1; \
    openssl x509 -req -in "$OVPN_PKI/server.csr" -CA "$OVPN_PKI/ca.crt" -CAkey "$OVPN_PKI/ca.key" -CAcreateserial -out "$OVPN_PKI/server.crt" -days 3650 -sha256 >/dev/null 2>&1; }
  [ -f "$OVPN_PKI/${CLIENT}.crt" ] || { \
    openssl genrsa -out "$OVPN_PKI/${CLIENT}.key" 4096 >/dev/null 2>&1; \
    openssl req -new -key "$OVPN_PKI/${CLIENT}.key" -subj "/CN=${CLIENT}" -out "$OVPN_PKI/${CLIENT}.csr" >/dev/null 2>&1; \
    openssl x509 -req -in "$OVPN_PKI/${CLIENT}.csr" -CA "$OVPN_PKI/ca.crt" -CAkey "$OVPN_PKI/ca.key" -CAcreateserial -out "$OVPN_PKI/${CLIENT}.crt" -days 3650 -sha256 >/dev/null 2>&1; }
fi
openvpn --genkey secret /etc/openvpn/pki/tc.key 2>/dev/null || true

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
/etc/init.d/openvpn enable >/dev/null 2>&1
/etc/init.d/openvpn restart >/dev/null 2>&1

# ВАЖНО: определить PUB4 ДО генерации .ovpn
PUB4="$(ip -4 addr show dev "$WAN_IF" | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)"

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
$(cat /etc/openvpn/pki/private/${CLIENT}.key 2>/dev/null || cat /etc/openGvpn/pki/${CLIENT}.key)
</key>
EOCLI

# ---------- 9) Firewall: зона VPN, NAT v4/v6, порт ----------
say "Настраиваю firewall (зона VPN, NAT v4/v6, порт ${OPORT}/udp)"
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
  warn "Не нашёл WAN‑зону — masq/masq6 пропускаю."
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
/etc/init.d/firewall restart >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1

# ---------- 10) TTL — интерактив ----------
say "TTL‑фикс"
echo " 1) Не менять TTL"
echo " 2) Компенсировать +1 (ttl=ttl+1; hoplimit=+1)"
echo " 3) Зафиксировать TTL (по умолчанию 127)"
printf "Выбор [1/2/3, по умолчанию 3]: "
read -r TTLMODE; [ -z "$TTLMODE" ] && TTLMODE=3
case "$TTLMODE" in
  1)
    rm -f /etc/nftables.d/95-ttlfix.nft
    /etc/init.d/firewall restart >/dev/null 2>&1
    ;;
  2)
    cat >/etc/nftables.d/95-ttlfix.nft <<NFT2
# include внутрь table inet fw4
chain xrl_ttl_post {
  type route hook postrouting priority mangle; policy accept;
  oifname "${WAN_IF}" ip ttl set ip ttl + 1; ip6 hoplimit set ip6 hoplimit + 1
}
NFT2
    /etc/init.d/firewall restart >/dev/null 2>&1
    ;;
  3|*)
    printf "TTL значение (Enter=127): "; read -r TTLV; [ -z "$TTLV" ] && TTLV=127
    cat >/etc/nftables.d/95-ttlfix.nft <<NFT3
# include внутрь table inet fw4
chain xrl_ttl_post {
  type route hook postrouting priority mangle; policy accept;
  oifname "${WAN_IF}" ip ttl set ${TTLV}; ip6 hoplimit set ${TTLV}
}
NFT3
    /etc/init.d/firewall restart >/dev/null 2>&1
    ;;
esac

# ---------- 11) Итоги ----------
say "ГОТОВО!"
IP4="$(ip -4 addr show dev "$WAN_IF" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
IP6="$(ip -6 addr show dev "$WAN_IF" scope global | awk '/inet6 /{print $2}' | cut -d/ -f1)"
echo "LuCI (HTTPS): https://${IP4}"
[ -n "$IP6" ] && echo "LuCI (IPv6): https://[${IP6}]/"
echo "Учётка LuCI/SSH: root ; пароль: ${PW_STATUS}"
echo "Passwall: LuCI → Services → Passwall (если установлен)"
echo "OpenVPN профиль (клиент): /root/${CLIENT}.ovpn"
echo "Проверка TPROXY:  nft list ruleset | sed -n '/xray_preroute/,/}/p'"
echo "Логи: Xray /var/log/xray/*.log | OpenVPN 'logread -e openvpn'"
EOF

chmod +x /root/road-warrior.sh
sh /root/road-warrior.sh
