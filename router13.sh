cat >/root/road-warrior.sh <<'EOF'
#!/bin/sh
# Road-Warrior for OpenWrt 24.10.x (x86_64)
# LuCI + (опц.) luci-app-xray + Xray(TPROXY+DNS) + OpenVPN (no-enc) + IPv6 + интерактив TTL

# ---------- утилиты вывода ----------
say()  { printf "\033[1;32m[RW]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[RW]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[RW]\033[0m %s\n" "$*"; }

# ---------- helpers ----------
cidr2mask() { bits="${1#*/}"; [ -z "$bits" ] && { echo 255.255.255.0; return; }
  m=0; i=0; while [ $i -lt 32 ]; do [ $i -lt "$bits" ] && m=$((m | (1<<(31-i)))); i=$((i+1)); done
  printf "%d.%d.%d.%d" $(( (m>>24)&255 )) $(( (m>>16)&255 )) $(( (m>>8)&255 )) $(( m&255 )); }
wan_zone_idx(){ uci show firewall 2>/dev/null | sed -n "s/^firewall\.@zone\[\([0-9]\+\)\]\.name='wan'.*/\1/p" | head -n1; }

ask_def() { # ask_def "Вопрос" "дефолт" -> stdout=ответ/дефолт
  prompt="$1"; def="$2"
  printf "%s [%s]: " "$prompt" "$def"
  read ans
  [ -z "$ans" ] && ans="$def"
  printf "%s" "$ans"
}

ask_yn() { # ask_yn "Вопрос" "Y|N"
  q="$1"; def="$2"
  case "$def" in Y|y) d="[Y/n]"; ret=Y;; *) d="[y/N]"; ret=N;; esac
  printf "%s %s: " "$q" "$d"
  read a
  [ -z "$a" ] && a="$ret"
  case "$a" in Y|y) return 0;; *) return 1;; esac
}

set_root_password() {
  say "Установка пароля root (для SSH и LuCI)"
  printf "Новый пароль (символы не отображаются): "
  stty -echo 2>/dev/null; read P1; stty echo 2>/dev/null; printf "\nПовторите пароль: "
  stty -echo 2>/dev/null; read P2; stty echo 2>/dev/null; printf "\n"
  if [ -n "$P1" ] && [ "$P1" = "$P2" ]; then
    printf "%s\n%s\n" "$P1" "$P1" | passwd root >/dev/null 2>&1 && say "Пароль root задан."
    ROOT_PASS_SET=1
  else
    warn "Пароли пустые или не совпали — пароль не изменён."
  fi
}

# ---------- 0) Автоопределение WAN ----------
WAN_IF="$(ubus call network.interface.wan status 2>/dev/null | sed -n 's/.*"l3_device":"\([^"]*\)".*/\1/p')"
[ -z "$WAN_IF" ] && WAN_IF="$(ip route | awk '/default/ {print $5; exit}')"
[ -z "$WAN_IF" ] && WAN_IF="eth0"
has_v4(){ ip -4 addr show dev "$WAN_IF" | grep -q 'inet '; }

if ! has_v4; then
  warn "IPv4 по DHCP не получен на $WAN_IF — настраиваю WAN=DHCP..."
  uci -q delete network.wan; uci -q delete network.wan6
  uci set network.wan='interface'; uci set network.wan.device="$WAN_IF"; uci set network.wan.proto='dhcp'
  uci commit network; /etc/init.d/network restart; sleep 4
fi

# ---------- 1) Интерактивные параметры ----------
say "== Параметры OpenVPN и сети =="
OPORT="$(ask_def 'Порт OpenVPN (UDP)' '1194')"
VPN4_NET="$(ask_def 'Подсеть VPN IPv4 (CIDR)' '10.99.0.0/24')"
VPN6_NET="$(ask_def 'Подсеть VPN IPv6 (ULA CIDR)' 'fd42:4242:4242:1::/64')"
CLIENT="$(ask_def 'Имя OpenVPN‑клиента' 'client1')"

say "== LuCI / Xray GUI =="
if ask_yn "Пытаться автоматически поставить luci-app-xray (GUI для Xray)?" "Y"; then
  INSTALL_LUCI_XRAY=1
  if ask_yn "Если GitHub вернёт 404 — спросить прямую ссылку .ipk и поставить с неё?" "Y"; then
    LUCI_XRAY_URL_FALLBACK=1
  fi
else
  INSTALL_LUCI_XRAY=0
fi

say "== Пароль для LuCI/SSH =="
if ask_yn "Задать пароль root сейчас?" "Y"; then
  SET_ROOT_PASS=1
else
  SET_ROOT_PASS=0
fi

# ---------- 2) distfeeds + opkg update ----------
say "Чиню distfeeds (packages-24.10) и обновляю индексы"
cp /etc/opkg/distfeeds.conf /etc/opkg/distfeeds.conf.bak 2>/dev/null
sed -i 's#https://downloads.openwrt.org/releases/[0-9.]\+/packages/x86_64/#https://downloads.openwrt.org/releases/packages-24.10/x86_64/#g' /etc/opkg/distfeeds.conf
opkg update || warn "opkg update вернул ошибку — продолжаю"

# ---------- 3) Пакеты ----------
say "Устанавливаю пакеты (LuCI, Xray, OpenVPN, nft tproxy, dnsmasq-full, утилиты)"
opkg install -V1 luci luci-ssl luci-compat ca-bundle curl wget jq ip-full openssl-util || true
opkg remove dnsmasq 2>/dev/null || true; opkg install dnsmasq-full || true
opkg install xray-core 2>/dev/null || opkg install xray-core || true
opkg install v2ray-geoip v2ray-geosite 2>/dev/null || opkg install xray-geodata 2>/dev/null || true
opkg install nftables kmod-nft-tproxy || true
opkg install openvpn-openssl openvpn-easy-rsa || true
opkg install nano 2>/dev/null || true
mkdir -p /etc/nftables.d

# ---------- 4) LuCI и (опц.) luci-app-xray ----------
/etc/init.d/uhttpd enable 2>/dev/null; /etc/init.d/uhttpd start 2>/dev/null

if [ "$INSTALL_LUCI_XRAY" = "1" ]; then
  say "Ставлю luci-app-xray (GUI)"
  opkg install luci-app-xray 2>/dev/null || true
  if ! opkg list-installed | grep -q '^luci-app-xray'; then
    warn "luci-app-xray нет в фидах — пытаюсь взять из Releases"
    URL=""
    HDRS="-H Accept:application/vnd.github+json -H User-Agent:curl/8"
    [ -n "$GITHUB_TOKEN" ] && HDRS="$HDRS -H Authorization:Bearer\ $GITHUB_TOKEN"
    URL="$(eval curl -fsSL $HDRS https://api.github.com/repos/yichya/luci-app-xray/releases/latest 2>/dev/null \
          | jq -r '.assets[]?.browser_download_url' | grep -E 'luci-app-xray_.*_all\.ipk$' | head -n1)"
    if [ -z "$URL" ]; then
      REL=$(curl -fsSL -H 'User-Agent:Mozilla/5.0' https://github.com/yichya/luci-app-xray/releases/latest 2>/dev/null | tr '\n' ' ')
      URL=$(echo "$REL" | grep -Eo '/yichya/luci-app-xray/releases/download/[^"]*luci-app-xray_[^"]*_all\.ipk' | head -n1)
      [ -n "$URL" ] && URL="https://github.com$URL"
    fi
    if [ -n "$URL" ]; then
      wget -O /tmp/luci-app-xray.ipk "$URL" 2>/dev/null && opkg install /tmp/luci-app-xray.ipk || warn "Не удалось поставить из Releases."
    else
      warn "Автоскачивание .ipk не удалось."
      if [ "$LUCI_XRAY_URL_FALLBACK" = "1" ]; then
        printf "Вставьте ПРЯМУЮ ссылку на luci-app-xray_..._all.ipk (или Enter чтобы пропустить): "
        read LUCI_IPK_URL
        if [ -n "$LUCI_IPK_URL" ]; then
          wget -O /tmp/luci-app-xray.ipk "$LUCI_IPK_URL" && opkg install /tmp/luci-app-xray.ipk || warn "Не удалось поставить с вашей ссылки."
        fi
      fi
    fi
  fi
fi

# ---------- 5) Xray: TPROXY + DNS ----------
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
    "rules": [{ "type": "field", "inboundTag": ["tproxy-in"], "port": 53, "outboundTag": "dns-out" }] }
}
JSON
/etc/init.d/xray enable 2>/dev/null; /etc/init.d/xray restart 2>/dev/null

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

# ---------- 7) nft TPROXY (include в fw4; IPv4+IPv6) ----------
say "Вкатываю nft-правила TPROXY (fw4 include на tun0 → :12345)"
cat >/etc/nftables.d/90-xray-tproxy.nft <<'NFT'
# Включается внутрь table inet fw4
set xray_v4_skip { type ipv4_addr; flags interval; elements = {
  127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4
} }
set xray_v6_skip { type ipv6_addr; flags interval; elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 } }

chain xray_preroute {
  type filter hook prerouting priority mangle; policy accept;

  # DNS (v4/v6) сначала
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
/etc/init.d/firewall restart 2>/dev/null || true

# ---------- 8) OpenVPN (UDP/TUN) без шифрования + PKI ----------
say "Готовлю PKI (EasyRSA/OpenSSL)"
EASYRSA_DIR="/etc/easy-rsa"; EASYRSA_PKI="$EASYRSA_DIR/pki"; mkdir -p "$EASYRSA_DIR" "$EASYRSA_PKI"
if opkg list-installed | grep -q '^openvpn-easy-rsa'; then
  EASYRSA_BIN="$(command -v easyrsa || echo /etc/easy-rsa/easyrsa)"
  [ -f "$EASYRSA_PKI/ca.crt" ] || { EASYRSA_BATCH=1 EASYRSA_PKI="$EASYRSA_PKI" "$EASYRSA_BIN" init-pki >/dev/null 2>&1
                                    EASYRSA_BATCH=1 EASYRSA_PKI="$EASYRSA_PKI" "$EASYRSA_BIN" build-ca nopass >/dev/null 2>&1; }
  [ -f "$EASYRSA_PKI/issued/server.crt" ] || EASYRSA_BATCH=1 EASYRSA_PKI="$EASYRSA_PKI" "$EASYRSA_BIN" build-server-full server nopass >/dev/null 2>&1
  [ -f "$EASYRSA_PKI/issued/${CLIENT}.crt" ] || EASYRSA_BATCH=1 EASYRSA_PKI="$EASYRSA_PKI" "$EASYRSA_BIN" build-client-full "$CLIENT" nopass >/dev/null 2>&1
  mkdir -p /etc/openvpn/pki; cp -r "$EASYRSA_PKI/"* /etc/openvpn/pki/ 2>/dev/null || true
else
  OVPN_PKI=/etc/openvpn/pki; mkdir -п "$OVPN_PKI"
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

OVPN4="${VPN4_NET%/*}"; MASK4="$(cidr2mask "$VPN4_NET")"

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
/etc/init.d/openvpn enable 2>/dev/null; /etc/init.d/openvpn restart 2>/dev/null

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
$(cat /etc/openvpn/pki/private/${CLIENT}.key 2>/dev/null || cat /etc/openvpn/pki/${CLIENT}.key)
</key>
EOCLI

# ---------- 9) Firewall: зона VPN, NAT4/NAT6, порт UDP ----------
say "Настраиваю firewall (зона VPN, NAT v4/v6, порт ${OPORT}/udp)"
uci -q delete network.vpn
uci add network interface; uci set network.@interface[-1].ifname='tun0'
uci set network.@interface[-1].proto='none'; uci set network.@interface[-1].auto='1'
uci rename network.@interface[-1]='vpn'; uci commit network

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
  warn "Не нашёл WAN‑зону — masq/masq6 пропущены"
fi

uci add firewall forwarding; uci set firewall.@forwarding[-1].src='vpn'; uci set firewall.@forwarding[-1].dest='wan'
uci add firewall rule; uci set firewall.@rule[-1].name='Allow-OpenVPN'
uci set firewall.@rule[-1].src='wan'; uci set firewall.@rule[-1].proto='udp'
uci set firewall.@rule[-1].dest_port="$OPORT"; uci set firewall.@rule[-1].target='ACCEPT'
uci commit firewall
/etc/init.d/firewall restart 2>/dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1

# ---------- 10) TTL (интерактив) ----------
say "TTL‑фикс:"
echo " 1) Не менять TTL (если ранее был фикс — удалить его)"
echo " 2) Компенсировать +1 (ttl=ttl+1; hoplimit=+1)"
echo " 3) Зафиксировать конкретный TTL (по умолчанию 127)"
printf "Выбор [1/2/3, Enter=3]: "; read TTLMODE; [ -z "$TTLMODE" ] && TTLMODE=3
case "$TTLMODE" in
  1)
    say "Удаляю TTL‑фикс (если был)"
    rm -f /etc/nftables.d/95-ttlfix.nft
    /etc/init.d/firewall restart 2>/dev/null
    ;;
  2)
    cat >/etc/nftables.d/95-ttlfix.nft <<NFT2
# include внутрь table inet fw4
chain xrl_ttl_post {
  type route hook postrouting priority mangle; policy accept;
  oifname "${WAN_IF}" ip ttl set ip ttl + 1; ip6 hoplimit set ip6 hoplimit + 1
}
NFT2
    /etc/init.d/firewall restart 2>/dev/null
    ;;
  3|*)
    printf "TTL значение (Enter=127): "; read TTLV; [ -z "$TTLV" ] && TTLV=127
    cat >/etc/nftables.d/95-ttlfix.nft <<NFT3
# include внутрь table inet fw4
chain xrl_ttl_post {
  type route hook postrouting priority mangle; policy accept;
  oifname "${WAN_IF}" ip ttl set ${TTLV}; ip6 hoplimit set ${TTLV}
}
NFT3
    /etc/init.d/firewall restart 2>/dev/null
    ;;
esac

# ---------- 11) Пароль root (если выбран) ----------
ROOT_PASS_SET=0
if [ "$SET_ROOT_PASS" = "1" ]; then
  set_root_password
fi

# ---------- 12) Резюме ----------
IP4="$(ip -4 addr show dev "$WAN_IF" | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)"
IP6="$(ip -6 addr show dev "$WAN_IF" scope global | awk '/inet6 /{print $2}' | cut -d/ -f1)"

say "ГОТОВО!"
echo "• LuCI по VPN:             https://10.99.0.1  (после подключения OpenVPN)"
echo "• LuCI по WAN (может блокироваться фаерволом): https://${IP4}"
[ -n "$IP6" ] && echo "• LuCI по IPv6:            https://[${IP6}]/"
echo "• Логин/пароль LuCI/SSH:   root / $( [ \"$ROOT_PASS_SET\" = \"1\" ] && echo 'установлен' || echo 'не задан — выполните passwd' )"
echo "• Xray GUI:                LuCI → Services → Xray (если luci-app-xray установлен)"
echo "• OpenVPN профиль:         /root/${CLIENT}.ovpn (импортируйте в OpenVPN GUI 2.5/2.6)"
echo "• Проверка TPROXY:         nft list ruleset | sed -n '/xray_preroute/,/}/p'"
echo "• Логи:                    tail -f /var/log/xray/access.log  |  logread -e openvpn"
EOF

chmod +x /root/road-warrior.sh
sh /root/road-warrior.sh
