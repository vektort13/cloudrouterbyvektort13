#!/bin/sh
# Road-Warrior for OpenWrt 24.10 (x86_64, DigitalOcean)
# LuCI + (опц.) Passwall GUI + Xray(TPROXY+DNS+опц.Socks5) + OpenVPN(no-enc) + IPv6 + интерактив TTL

say()  { printf "\033[1;32m[RW]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[RW]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[RW]\033[0m %s\n" "$*"; }

# ---------- helpers ----------
ask_var() { # ask_var "Вопрос" VAR "дефолт"
  local _q="$1" _name="$2" _def="$3" _val
  printf "%s [%s]: " "$_q" "$_def"
  read -r _val
  eval "$_name=\"${_val:-$_def}\""
}
ask_yn() { # ask_yn "Вопрос" "Y|N"
  local q="$1" def="${2:-Y}" a
  case "$def" in Y|y) printf "%s [Y/n]: " "$q" ;; *) printf "%s [y/N]: " "$q" ;; esac
  read -r a
  [ -z "$a" ] && a="$def"
  case "$a" in Y|y) return 0 ;; *) return 1 ;; esac
}
cidr2mask() {
  bits="${1#*/}"; [ -z "$bits" ] || [ "$bits" = "$1" ] && { echo 255.255.255.0; return; }
  m=0; i=0; while [ $i -lt 32 ]; do [ $i -lt "$bits" ] && m=$((m | (1<<(31-i)))); i=$((i+1)); done
  printf "%d.%d.%d.%d" $(( (m>>24)&255 )) $(( (m>>16)&255 )) $(( (m>>8)&255 )) $(( m&255 ))
}
wan_zone_idx(){ uci show firewall 2>/dev/null | sed -n "s/^firewall\.@zone\[\([0-9]\+\)\]\.name='wan'.*/\1/p" | head -n1; }
has_v4(){ ip -4 addr show dev "$WAN_IF" | grep -q 'inet '; }
is_port(){ case "$1" in ''|*[!0-9]* ) return 1;; * ) [ "$1" -ge 1 ] && [ "$1" -le 65535 ];; esac }

# ---------- 0) Приветствие + ввод ----------
say "Интерактивный мастер (Enter — принять значение в [скобках])"

# Автодетект WAN
DET_WAN="$(ubus call network.interface.wan status 2>/dev/null | sed -n 's/.*"l3_device":"\([^"]*\)".*/\1/p')"
[ -z "$DET_WAN" ] && DET_WAN="$(ip route | awk '/default/ {print $5; exit}')"
[ -z "$DET_WAN" ] && DET_WAN="eth0"
ask_var "Имя WAN-интерфейса" WAN_IF "$DET_WAN"

ask_var "Порт OpenVPN (UDP)" OPORT "1194"
is_port "$OPORT" || { err "Неверный порт: $OPORT"; exit 1; }

ask_var "Имя OpenVPN-клиента (CN)" CLIENT "client1"
ask_var "VPN IPv4-подсеть (CIDR)" VPN4_NET "10.99.0.0/24"
ask_var "VPN IPv6 ULA /64" VPN6_NET "fd42:4242:4242:1::/64"

PW_STATUS="не изменён"
if ask_yn "Задать пароль root для LuCI/SSH сейчас?" "Y"; then
  printf "Введите НОВЫЙ пароль root: "
  stty -echo 2>/dev/null; read -r NEWPW; stty echo 2>/dev/null; echo
  if [ -n "$NEWPW" ]; then
    printf "%s\n%s\n" "$NEWPW" "$NEWPW" | passwd root >/dev/null 2>&1 && PW_STATUS="установлен" || PW_STATUS="ошибка"
  fi
fi

# Кто управляет прокси/TPROXY?
MODE="A"
if ask_yn "Использовать Passwall как GUI-менеджер прокси/TPROXY (рекомендуется)?" "Y"; then
  MODE="B"
fi

# ---------- 1) Фиды + базовые пакеты ----------
say "Обновляю фиды и ставлю зависимости"
cp /etc/opkg/distfeeds.conf /etc/opkg/distfeeds.conf.bak 2>/dev/null || true
sed -i 's#https://downloads.openwrt.org/releases/[0-9.]\+/packages/x86_64/#https://downloads.openwrt.org/releases/packages-24.10/x86_64/#g' /etc/opkg/distfeeds.conf
opkg update || true

for p in luci luci-ssl luci-compat luci-app-openvpn ca-bundle curl wget jq ip-full openssl-util; do opkg install -V1 "$p" || true; done
opkg remove dnsmasq 2>/dev/null || true; opkg install dnsmasq-full || true
opkg install xray-core || true
opkg install v2ray-geoip v2ray-geosite 2>/dev/null || opkg install xray-geodata 2>/dev/null || true
opkg install nftables kmod-nft-tproxy nftables-json || true
opkg install openvpn-openssl kmod-tun openvpn-easy-rsa 2>/dev/null || true
opkg install unzip nano 2>/dev/null || true

# ---------- 2) WAN bring-up при необходимости ----------
if ! has_v4; then
  warn "IPv4 на $WAN_IF не получен — настраиваю WAN=DHCP"
  uci -q delete network.wan; uci -q delete network.wan6
  uci set network.wan='interface'
  uci set network.wan.device="$WAN_IF"
  uci set network.wan.proto='dhcp'
  uci commit network
  /etc/init.d/network restart
  sleep 5
  has_v4 || warn "DHCP не выдал IPv4. Проверьте сеть (ip a, ping 8.8.8.8)."
fi

# ---------- 3) Passwall (опционально) ----------
install_passwall_luci_from_github() {
  # используем конкретный релиз (можно поменять на актуальный)
  PW_TAG="${1:-25.11.1-1}"
  say "Скачиваю luci-app-passwall из GitHub (тег ${PW_TAG})"
  URL="$(curl -fsSL -H 'User-Agent: curl' "https://github.com/xiaorouji/openwrt-passwall/releases/tag/${PW_TAG}" 2>/dev/null \
      | tr '\n' ' ' | grep -Eo '/xiaorouji/openwrt-passwall/releases/download/[^"]*luci-24\.10_luci-app-passwall_[^"]*_all\.ipk' | head -n1)"
  [ -n "$URL" ] && URL="https://github.com${URL}"
  [ -z "$URL" ] && { warn "Не нашёл ссылку на .ipk для ${PW_TAG}"; return 1; }
  uclient-fetch -O /tmp/luci-app-passwall.ipk "$URL" 2>/dev/null || wget -O /tmp/luci-app-passwall.ipk "$URL" || return 2
  opkg install /tmp/luci-app-passwall.ipk || return 3
  say "luci-app-passwall установлен."
  return 0
}

if [ "$MODE" = "B" ]; then
  say "Устанавливаю Passwall GUI (вариант: прямой .ipk с релиза)"
  install_passwall_luci_from_github || warn "Авто-установка Passwall не удалась. Можно поставить вручную из .ipk."
fi

# ---------- 4) LuCI ----------
/etc/init.d/uhttpd enable >/dev/null 2>&1
/etc/init.d/uhttpd start  >/dev/null 2>&1

# ---------- 5) Xray/TPROXY ----------
if [ "$MODE" = "A" ]; then
  say "Режим A (стэндэлон): настраиваю Xray TPROXY + (опц.) Socks5"
  mkdir -p /etc/xray /var/log/xray

  # опционально Socks5 на сервере
  SOCKS_PORT=""
  if ask_yn "Включить локальный Socks5 на VPS?" "Y"; then
    ask_var "Порт Socks5" SOCKS_PORT "1080"
    if ask_yn "Требовать логин/пароль для Socks5?" "Y"; then
      printf "Логин Socks5: "; read -r SOCKS_USER
      printf "Пароль Socks5: "; read -r SOCKS_PASS
      [ -n "$SOCKS_USER" ] && [ -n "$SOCKS_PASS" ] || { warn "Пустые user/pass — будет без авторизации"; SOCKS_USER=""; SOCKS_PASS=""; }
    fi
  fi

  # формируем inbounds JSON
  XRAY_INBOUNDS='{
    "tag": "tproxy-in",
    "protocol": "dokodemo-door",
    "port": 12345,
    "settings": { "network": "tcp,udp", "followRedirect": true },
    "streamSettings": { "sockopt": { "tproxy": "tproxy" } }
  }'
  if [ -n "$SOCKS_PORT" ]; then
    if [ -n "$SOCKS_USER" ] && [ -n "$SOCKS_PASS" ]; then
      SOCKS_AUTH='"auth":"password","accounts":[{"user":"'"$SOCKS_USER"'","pass":"'"$SOCKS_PASS"'"}],'
    else
      SOCKS_AUTH='"auth":"noauth",'
    fi
    XRAY_INBOUNDS="${XRAY_INBOUNDS},
    {\"tag\":\"socks-in\",\"protocol\":\"socks\",\"port\":${SOCKS_PORT},
     \"settings\":{${SOCKS_AUTH}\"udp\":true},
     \"sniffing\":{\"enabled\":true,\"destOverride\":[\"http\",\"tls\"]}}"
  fi

  cat > /etc/xray/config.json <<JSON
{
  "log": { "loglevel": "warning", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log" },
  "inbounds": [ ${XRAY_INBOUNDS} ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    { "tag": "dns-out", "protocol": "dns", "settings": { "address": "8.8.8.8" } }
  ],
  "dns": { "servers": [ "8.8.8.8", "1.1.1.1", "https+local://dns.cloudflare.com/dns-query" ] },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["tproxy-in"], "port": 53, "outboundTag": "dns-out" }
    ]
  }
}
JSON

  /etc/init.d/xray enable >/dev/null 2>&1
  /etc/init.d/xray restart >/dev/null 2>&1

  # policy routing (fwmark 0x1 -> table 100)
  say "Policy routing (fwmark 0x1 -> table 100)"
  ip rule add fwmark 0x1 table 100 2>/dev/null || true
  ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
  ip -6 rule add fwmark 0x1 table 100 2>/dev/null || true
  ip -6 route add local ::/0 dev lo table 100 2>/dev/null || true

  mkdir -p /etc/hotplug.d/iface
  cat > /etc/hotplug.d/iface/99-xray-tproxy <<'HPL'
#!/bin/sh
[ "$ACTION" = "ifup" ] || exit 0
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

  # nft TPROXY (ВАЖНО: без объявления table — фрагмент включается внутрь inet fw4)
  say "nft TPROXY правила (перехват трафика с tun0)"
  mkdir -p /etc/nftables.d
  cat > /etc/nftables.d/90-xray-tproxy.nft <<'NFT'
# включается внутрь table inet fw4
set xray_v4_skip { type ipv4_addr; flags interval; elements = { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } }
set xray_v6_skip { type ipv6_addr; flags interval; elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 } }

chain xray_preroute {
  type filter hook prerouting priority mangle; policy accept;

  # DNS (v4/v6)
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
else
  say "Режим B (Passwall): пропускаю собственные Xray/nft/mark — настраивать через GUI Passwall."
  /etc/init.d/xray disable >/dev/null 2>&1 || true
  /etc/init.d/xray stop    >/dev/null 2>&1 || true
fi

# ---------- 6) OpenVPN (без шифрования) + PKI ----------
say "OpenVPN (без шифрования) + PKI"
if command -v easyrsa >/dev/null 2>&1; then
  EASYRSA_PKI="/etc/easy-rsa/pki"
  EASYRSA_BATCH=1 easyrsa init-pki >/dev/null 2>&1 || true
  [ -f "$EASYRSA_PKI/ca.crt" ]                  || EASYRSA_BATCH=1 easyrsa build-ca nopass >/dev/null 2>&1
  [ -f "$EASYRSA_PKI/issued/server.crt" ]       || EASYRSA_BATCH=1 easyrsa build-server-full server nopass >/dev/null 2>&1
  [ -f "$EASYRSA_PKI/issued/${CLIENT}.crt" ]    || EASYRSA_BATCH=1 easyrsa build-client-full "${CLIENT}" nopass >/dev/null 2>&1
  mkdir -p /etc/openvpn/pki; cp -r "$EASYRSA_PKI/"* /etc/openvpn/pki/ 2>/dev/null || true
else
  OVPN_PKI="/etc/openvpn/pki"; mkdir -p "$OVPN_PKI"
  [ -f "$OVPN_PKI/ca.crt" ] || { openssl genrsa -out "$OVPN_PKI/ca.key" 4096 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key "$OVPN_PKI/ca.key" -sha256 -days 3650 -subj "/CN=OpenWrt-CA" -out "$OVPN_PKI/ca.crt" >/dev/null 2>&1; }
  [ -f "$OVPN_PKI/server.crt" ] || { openssl genrsa -out "$OVPN_PKI/server.key" 4096 >/dev/null 2>&1
    openssl req -new -key "$OVPN_PKI/server.key" -subj "/CN=server" -out "$OVPN_PKI/server.csr" >/dev/null 2>&1
    openssl x509 -req -in "$OVPN_PKI/server.csr" -CA "$OVPN_PKI/ca.crt" -CAkey "$OVPN_PKI/ca.key" -CAcreateserial -out "$OVPN_PKI/server.crt" -days 3650 -sha256 >/dev/null 2>&1; }
  [ -f "$OVPN_PKI/${CLIENT}.crt" ] || { openssl genrsa -out "$OVPN_PKI/${CLIENT}.key" 4096 >/dev/null 2>&1
    openssl req -new -key "$OVPN_PKI/${CLIENT}.key" -subj "/CN=${CLIENT}" -out "$OVPN_PKI/${CLIENT}.csr" >/dev/null 2>&1
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
if [ -f "/etc/openvpn/pki/issued/server.crt" ]; then
  uci set openvpn.rw.cert='/etc/openvpn/pki/issued/server.crt'
  uci set openvpn.rw.key='/etc/openvpn/pki/private/server.key'
else
  uci set openvpn.rw.cert='/etc/openvpn/pki/server.crt'
  uci set openvpn.rw.key='/etc/openvpn/pki/server.key'
fi
uci set openvpn.rw.dh='none'
uci add_list openvpn.rw.push='redirect-gateway def1 ipv6'
uci add_list openvpn.rw.push='dhcp-option DNS 10.99.0.1'
uci add_list openvpn.rw.push='dhcp-option DNS6 fd42:4242:4242:1::1'
uci set openvpn.rw.tls_crypt='/etc/openvpn/pki/tc.key'
uci commit openvpn
/etc/init.d/openvpn enable >/dev/null 2>&1
/etc/init.d/openvpn restart >/dev/null 2>&1

PUB4="$(ip -4 addr show dev "$WAN_IF" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)"
[ -z "$PUB4" ] && PUB4="YOUR_SERVER_IP"
cat >"/root/${CLIENT}.ovpn" <<EOCLI
client
dev tun
proto udp
remote ${PUB4} ${OPORT}
nobind
persist-key
persist-tun
verb 3
explicit-exit-notify 1
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
$(cat /etc/openvpn/pki/issued/${CLIENT}.crt 2>/dev/null || cat /etc/openvpn/pki/${CLIENT}.crt 2>/dev/null)
</cert>
<key>
$(cat /etc/openvpn/pki/private/${CLIENT}.key 2>/dev/null || cat /etc/openvpn/pki/${CLIENT}.key 2>/dev/null)
</key>
EOCLI

# ---------- 7) Фаервол: зоны, NAT, порт OpenVPN (+Socks5) ----------
say "Настраиваю firewall (зона VPN, NAT, порт ${OPORT}/udp)"
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
  warn "WAN-зона не найдена; если WAN в LAN-зоне — включите маскарадинг там."
fi

uci add firewall forwarding
uci set firewall.@forwarding[-1].src='vpn'
uci set firewall.@forwarding[-1].dest="${WZ:+wan}${WZ:-lan}"

uci add firewall rule
uci set firewall.@rule[-1].name='Allow-OpenVPN'
uci set firewall.@rule[-1].src='wan'
uci set firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].dest_port="$OPORT"
uci set firewall.@rule[-1].target='ACCEPT'

# Разрешить Socks5, если включали
if [ "$MODE" = "A" ] && [ -n "$SOCKS_PORT" ]; then
  uci add firewall rule
  uci set firewall.@rule[-1].name='Allow-Socks5'
  uci set firewall.@rule[-1].src='wan'
  uci set firewall.@rule[-1].proto='tcp'
  uci set firewall.@rule[-1].dest_port="$SOCKS_PORT"
  uci set firewall.@rule[-1].target='ACCEPT'
  uci add firewall rule
  uci set firewall.@rule[-1].name='Allow-Socks5-UDP'
  uci set firewall.@rule[-1].src='wan'
  uci set firewall.@rule[-1].proto='udp'
  uci set firewall.@rule[-1].dest_port="$SOCKS_PORT"
  uci set firewall.@rule[-1].target='ACCEPT'
fi

uci commit firewall
/etc/init.d/firewall restart >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1

# ---------- 8) TTL (интерактив) ----------
say "TTL фикс (для маскировки/совместимости)"
echo " 1) Не менять TTL"
echo " 2) Увеличить на +1 (IPv4 ttl и IPv6 hoplimit)"
echo " 3) Зафиксировать TTL (по умолчанию 127)"
printf "Выбор [1/2/3, Enter=3]: "; read -r TTLMODE; [ -z "$TTLMODE" ] && TTLMODE=3
mkdir -p /etc/nftables.d
case "$TTLMODE" in
  1) rm -f /etc/nftables.d/95-ttlfix.nft ;;
  2) cat > /etc/nftables.d/95-ttlfix.nft <<NFT
# include внутрь table inet fw4
chain ttl_fix_out {
  type route hook postrouting priority mangle; policy accept;
  oifname "${WAN_IF}" ip ttl set ip ttl + 1
  oifname "${WAN_IF}" ip6 hoplimit set ip6 hoplimit + 1
}
NFT
  ;;
  3|*)
    printf "TTL значение (Enter=127): "; read -r TTLV; [ -z "$TTLV" ] && TTLV=127
    cat > /etc/nftables.d/95-ttlfix.nft <<NFT
# include внутрь table inet fw4
chain ttl_fix_out {
  type route hook postrouting priority mangle; policy accept;
  oifname "${WAN_IF}" ip ttl set ${TTLV}
  oifname "${WAN_IF}" ip6 hoplimit set ${TTLV}
}
NFT
  ;;
esac
/etc/init.d/firewall restart >/dev/null 2>&1

# ---------- 9) Резюме ----------
IP4="$(ip -4 addr show dev "$WAN_IF" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
IP6="$(ip -6 addr show dev "$WAN_IF" scope global | awk '/inet6 /{print $2}' | cut -d/ -f1 | head -n1)"
say "ГОТОВО!"
[ -n "$IP4" ] && echo "LuCI (IPv4): https://${IP4}"
[ -n "$IP6" ] && echo "LuCI (IPv6): https://[${IP6}]/"
echo "Учётка LuCI/SSH: root / ${PW_STATUS}"
[ -n "$SOCKS_PORT" ] && echo "Socks5: ${IP4:-<VPS_IP>}:${SOCKS_PORT} $( [ -n "$SOCKS_USER" ] && echo "(auth)" || echo "(noauth)" )"
[ "$MODE" = "B" ] && echo "Passwall: LuCI → Services → Passwall (включите «Main switch», TProxy, выберите узлы TCP/UDP)"
echo "OpenVPN профиль клиента: /root/${CLIENT}.ovpn"
echo "Проверка TPROXY: nft list ruleset | sed -n '/xray_preroute/,/}/p'"
echo "Логи: Xray /var/log/xray/*.log | OpenVPN: logread -e openvpn"
