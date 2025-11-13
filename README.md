# AntiDetect Router (alpha) v.0.1.0

> **Status:** ⚠️ Early alpha – expect bugs, rough edges and sharp corners.  
> **Author:** Vektor T13  
> **Website:** [detect.expert](https://detect.expert)

AntiDetect Router is a one‑shot shell script that turns a clean OpenWrt 24.10.x (x86_64) VPS into a **VPS‑friendly “road‑warrior” hub** with:

- an inbound **OpenVPN server** for your devices,  
- optional **outbound VPN / proxy chain** via Passwall + Xray/sing‑box,  
- **policy‑based routing (PBR)** that sends VPN clients out through external tun* interfaces,  
- smart **DNS routing** that automatically follows the active outbound VPN,  
- a minimal **web landing page** to grab your `.ovpn` file and LuCI login details.

Everything is configured automatically from a single script: certificates, OpenVPN, nftables, routing tables, LuCI, DNS, and helper utilities.

---

## ⚠️ IMPORTANT WARNINGS – READ BEFORE USE

> ❗ This project is an **alpha‑stage tool for advanced users**, not a polished consumer product.

- **IPv6 support vs VPS providers**  
  The script includes full logic for **IPv6 routing and OpenVPN IPv6 pools**.  
  However, some VPS providers (for example, DigitalOcean with custom OS images) **do not properly support IPv6 on custom images**.  
  If your provider breaks or silently ignores IPv6 on custom OpenWrt images, IPv6 parts of this setup will not work as intended.  
  👉 **Choose a sane VPS provider** that:
  - gives you real IPv6 addresses, and  
  - supports IPv6 correctly for your chosen image (including OpenWrt).

- **Outbound VPN with username/password authentication**  
  The script itself does not hard‑code any specific username/password for outbound VPNs.  
  If your upstream VPN **requires login/password authentication**, you’ll need to adjust the outbound OpenVPN / Passwall node configuration accordingly.  
  For a practical, step‑by‑step explanation on how to wire authentication correctly, **watch the training video on the YouTube channel _VectorT13_** and follow the recommended auth layout there.

- **Alpha quality**  
  - Configs, defaults and behaviour **may change** between versions.  
  - Do not rely on this for critical production infrastructure.  
  - Always test on a throwaway VPS before rolling it into anything serious.

---

## What this project is

AntiDetect Router is designed for **VPS installations of OpenWrt 24.10.x (x86_64)** – for example on DigitalOcean and similar providers. The script assumes:

- a publicly routable IPv4 address,  
- OpenWrt preinstalled on the VPS,  
- root access via SSH.

After running the script, you get:

- a **ready‑to‑use OpenVPN “road‑warrior” server** (`tun0`) for your devices,  
- a configurable **pass‑through / “double‑hop” pipeline** where:
  - clients connect _into_ your VPS via your OpenVPN server,  
  - their traffic exits _out_ via an **external VPN / proxy** (tunX or Passwall backend),  
- a **fixed management path**: the router itself (SSH / LuCI) always goes directly via the VPS’ public interface, never through the outbound VPN.

This makes the box behave more like an **“AntiDetect edge node”** than just a simple VPN server.

---

## Core components

The script wires up the following building blocks:

## Target OS / reference image

AntiDetect Router (alpha) was developed and tested on:

- **OpenWrt 24.10.4 (x86/64)**
  - Official download tree: `https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/`
  - Reference image: `generic-ext4-combined-efi.img.gz`

Other OpenWrt 24.10.x x86_64 builds may work, but the image above is the **reference environment** this script was built and verified against.

### Base system

- **OS:** OpenWrt 24.10.x (x86_64)  
- **Web UI:** LuCI + `uhttpd` (HTTPS enabled)  
- **Resolver:** `dnsmasq-full`  
- **Firewall:** built‑in `fw4` service is stopped; all NAT/PBR logic uses **raw nftables + iproute2** instead.

### VPN core

- **VPN server:** `openvpn-openssl` (road‑warrior style, `dev tun`)  
- **Topology:** `topology subnet` + IPv4/IPv6 server pools  
- **Crypto / data plane:**
  - `cipher none`
  - `auth none`
  - TLS 1.2+ with **TLS‑crypt** (`tc.key`) and a local CA
  - Encryption is handled at the TLS layer only; the data channel is intentionally “no‑cipher” for speed and simplicity.
- **Server features:**
  - Auto‑generated CA + server and client certificates
  - Auto‑generated client config file `<client>.ovpn`
  - `redirect-gateway def1` + `redirect-gateway ipv6` pushed to clients
  - DNS push: clients receive **VPN server’s tun0 IP** as DNS
  - Status + log files: `/tmp/openvpn-status.log`, `/tmp/openvpn.log`

### Outbound VPN / Proxy core

AntiDetect Router is designed to sit **between your devices and another exit‑node**:

- Optional **Passwall GUI**:
  - Feeds for `passwall_luci`, `passwall_packages`, `passwall2` are installed.
  - Installs **`luci-app-passwall`** or **`luci-app-passwall2`** (whichever succeeds).
- Proxy engines:
  - **`xray-core`** (preferred) _or_ **`sing-box`** as fallback.
- You can define:
  - Xray / sing‑box nodes,
  - Socks5/OpenVPN upstreams,
  - Access rules in **LuCI → Services → Passwall**.

The script does **not** create your proxy nodes for you; it simply ensures the stack is installed and ready.

---

## DNS behaviour

AntiDetect Router includes a fairly advanced DNS setup so that **DNS follows the active outbound VPN**:

1. **Clients’ DNS:**
   - OpenVPN server pushes `dhcp-option DNS <server-tun-IP>` to connecting clients.
   - `dnsmasq` listens on `tun0` and answers DNS for the RW subnet.

2. **Router’s upstream DNS logic:**
   - By default, `dnsmasq` uses the VPS’ **system resolvers** (from `resolv.conf.auto`).
   - When an **outbound OpenVPN client** is connected, an `up/down` hook script  
     `/etc/openvpn/rw-dyn-dns.sh`:
     - parses `foreign_option_n` for `dhcp-option DNS` from the remote server,
     - rewrites `dhcp.@dnsmasq[0].server` to point to those DNS servers,
     - pins them (optionally) to the outbound interface (`dev`),
     - on `down`, restores normal system DNS.

Result:  
- If outbound VPN is **up** → router + RW clients resolve through **DNS of that outbound VPN**.  
- If outbound VPN is **down** → everything falls back to **VPS’ own resolvers**.

---

## Routing & NAT

- **IP forwarding:** enabled for IPv4 and IPv6.  
- **Reverse path filtering:** disabled on all interfaces (for asymmetric routing across tun devices).  
- **Management table (`mgmt`):**
  - A dedicated `ip rule` + `rt_tables` entry ensures all traffic **from** the VPS’ public IP goes out via the main interface and default gateway.
  - Prevents SSH / LuCI from being accidentally routed into or through tun*.
- **RW client PBR:**
  - A separate table `vpnout` is created.
  - Traffic **coming from the OpenVPN server interface** (RW subnet) can be policy‑routed out via an external tunX (e.g. outbound OpenVPN client or Passwall chain).
- **NAT:**
  - `nftables` table `inet rwfix` with `postrouting` chain:
    - Masquerades all traffic **originating from the RW interface** (`tun0` by default) when it leaves through any other interface.

---

## LuCI & language support

The script installs LuCI and several language packs so the web UI can be localized:

- **Base LuCI translations:**
  - `luci-i18n-base-ru` – Russian  
  - `luci-i18n-base-zh-cn` – Simplified Chinese  
  - `luci-i18n-base-vi` – Vietnamese  
  - `luci-i18n-base-es` – Spanish  
- **App‑specific translations:**
  - `luci-i18n-openvpn-ru` – OpenVPN app in Russian  
  - `luci-i18n-firewall-ru` – Firewall app in Russian  

The core script messages and README are in **English**, but once you log into LuCI you can switch the interface language (System → System → Language and Style) to any installed locale.

---

## Generated artifacts & helper tools

After running the script you get:

- `/root/<client>.ovpn` — road‑warrior client profile.  
- `/www/vpn/<client>.ovpn` — same profile, downloadable over HTTPS.  
- `/www/vpn/index.html` — minimal landing page with:
  - download link for the client config,
  - LuCI URL (`https://<VPS_IP>`),
  - direct VPN config (`https://<VPS_IP>/vpn`),
  - root username and password reminder.
- `/usr/sbin/rw-fix` — “panic button” to:
  - remove hijacked `/1` default routes on tun+,
  - reset IPv4/IPv6 defaults,
  - restart `dnsmasq` and OpenVPN.

---

This is the **alpha** foundation of AntiDetect Router: a scripted, reproducible OpenWrt setup that glues together OpenVPN, advanced DNS behaviour, nftables‑based PBR, and Passwall/Xray/sing‑box into a single VPS‑ready router.
