#!/bin/sh
# shellcheck shell=dash
# Firewall abstraction layer for trafficctl.
# Detects nft vs iptables and provides unified functions.
# Source this file: . /usr/local/bin/trafficctl-fw.sh

if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q .; then
    TCTL_FW="nft"
else
    TCTL_FW="iptables"
fi

# ── Rate Limiting (policer) ────────────────────────────────────────────────

# Rate limits are symmetric: the same ceiling is policed in both directions.
#
# Download is caught at WAN ingress (packets arriving for the client) and
# upload at LAN ingress (packets the client sends into the router). Policing
# upload on the way IN is what makes it work for downstream/routed clients
# too — their packets still enter over a LAN device with the client's source
# address, whatever router sits behind it.
# mode: "each" gives every address inside the target its own bucket (an nft
# meter keyed by address); "shared" makes the whole target share one bucket.
# For a single host the two are identical.
tctl_ratelimit_add() {
    local ip="$1" rate_kbit="$2" comment="$3" mode="${4:-shared}"
    local rate_kbyte=$((rate_kbit / 8))
    [ "$rate_kbyte" -lt 1 ] && rate_kbyte=1

    local slug dl_expr ul_expr
    slug=$(tctl_target_slug "$ip")
    if [ "$mode" = "each" ]; then
        dl_expr="ip daddr $ip meter tctl_d_$slug { ip daddr limit rate over ${rate_kbyte} kbytes/second }"
        ul_expr="ip saddr $ip meter tctl_u_$slug { ip saddr limit rate over ${rate_kbyte} kbytes/second }"
    else
        dl_expr="ip daddr $ip limit rate over ${rate_kbyte} kbytes/second"
        ul_expr="ip saddr $ip limit rate over ${rate_kbyte} kbytes/second"
    fi

    if [ "$TCTL_FW" = "nft" ]; then
        nft add table netdev tm_ratelimit 2>/dev/null

        local wan_dev rc=0
        if wan_dev=$(tctl_get_wan_device); then
            nft add chain netdev tm_ratelimit dl \
                "{ type filter hook ingress device $wan_dev priority -200; policy accept; }" 2>/dev/null
            nft add rule netdev tm_ratelimit dl \
                "$dl_expr counter drop comment \"$comment\"" 2>/dev/null \
                || rc=1
        else
            rc=1
        fi
        # Set for the caller to inspect (see trafficctl-ratelimit.sh).
        # shellcheck disable=SC2034
        [ "$rc" = "0" ] || TCTL_RL_DOWNLOAD_FAILED=1

        # One chain per ingress device: a device that refuses the hook then
        # only loses its own chain instead of taking the whole set with it.
        local dev chain
        local ul_ok=0
        for dev in $(tctl_ingress_devices); do
            chain=$(tctl_ingress_chain "$dev")
            nft add chain netdev tm_ratelimit "$chain" \
                "{ type filter hook ingress device $dev priority -200; policy accept; }" 2>/dev/null
            nft add rule netdev tm_ratelimit "$chain" \
                "$ul_expr counter drop comment \"${comment}_ul\"" 2>/dev/null \
                && ul_ok=1
        done
        # shellcheck disable=SC2034
        [ "$ul_ok" = "1" ] || TCTL_RL_UPLOAD_FAILED=1
    else
        iptables -t mangle -A FORWARD -d "$ip" -m hashlimit \
            --hashlimit-above "${rate_kbit}kbit/sec" --hashlimit-burst "${rate_kbit}kbit" \
            --hashlimit-mode dstip --hashlimit-name "rl_${comment}" \
            -j DROP -m comment --comment "$comment" 2>/dev/null
        iptables -t mangle -A FORWARD -s "$ip" -m hashlimit \
            --hashlimit-above "${rate_kbit}kbit/sec" --hashlimit-burst "${rate_kbit}kbit" \
            --hashlimit-mode srcip --hashlimit-name "rl_${comment}_ul" \
            -j DROP -m comment --comment "${comment}_ul" 2>/dev/null
    fi
}

tctl_ratelimit_remove() {
    local ip="$1" comment="$2"
    local chain h

    if [ "$TCTL_FW" = "nft" ]; then
        # Scan the whole table once: rules for this IP live in dl (daddr) and
        # in one ul_<dev> chain per ingress device (saddr).
        nft -a list table netdev tm_ratelimit 2>/dev/null | awk -v cmt="$comment" '
            /^[ \t]*chain [a-zA-Z0-9_]+ \{/ { chain = $2; next }
            index($0, "\"" cmt "\"") || index($0, "\"" cmt "_ul\"") {
                for (i = 1; i < NF; i++)
                    if ($i == "handle") { print chain, $(i+1); break }
            }' | while read -r chain h; do
            [ -n "$chain" ] && [ -n "$h" ] && nft delete rule netdev tm_ratelimit "$chain" handle "$h" 2>/dev/null
        done
    else
        while iptables -t mangle -D FORWARD -d "$ip" -m comment --comment "$comment" 2>/dev/null; do :; done
        while iptables -t mangle -D FORWARD -s "$ip" -m comment --comment "${comment}_ul" 2>/dev/null; do :; done
    fi
}

tctl_ratelimit_list() {
    if [ "$TCTL_FW" = "nft" ]; then
        nft list table netdev tm_ratelimit 2>/dev/null
    else
        iptables -t mangle -L FORWARD -nv --line-numbers 2>/dev/null | grep "rl_ratelimit"
    fi
}

# ── Internet Blocking ──────────────────────────────────────────────────────

tctl_block_add() {
    local ip="$1" comment="$2"

    if [ "$TCTL_FW" = "nft" ]; then
        nft insert rule inet fw4 forward "ip saddr $ip counter drop comment \"$comment\""
    else
        iptables -I FORWARD -s "$ip" -j DROP -m comment --comment "$comment"
    fi
}

tctl_block_remove() {
    local ip="$1" comment="$2"

    if [ "$TCTL_FW" = "nft" ]; then
        for h in $(nft -a list chain inet fw4 forward 2>/dev/null \
                   | grep "$comment" | grep -o 'handle [0-9]*' | awk '{print $2}'); do
            nft delete rule inet fw4 forward handle "$h"
        done
    else
        while iptables -D FORWARD -s "$ip" -m comment --comment "$comment" -j DROP 2>/dev/null; do :; done
    fi
}

tctl_is_blocked() {
    local ip="$1"
    if [ "$TCTL_FW" = "nft" ]; then
        nft list chain inet fw4 forward 2>/dev/null | grep -q "ip saddr $ip .*drop"
    else
        iptables -L FORWARD -n 2>/dev/null | grep -q "DROP.*$ip"
    fi
}

# ── Helpers ────────────────────────────────────────────────────────────────

# Resolve the WAN device to a name that actually exists as a netdev.
#
# The old fallback returned the literal string "wan", which is an interface
# NAME, not a device — nft then rejected the chain ("device wan" doesn't
# exist), the failure was swallowed, and download limiting silently did
# nothing while still reporting success. Every candidate is now verified
# against sysfs, with the default route as a last resort.
tctl_get_wan_device() {
    local sysfs="${TCTL_SYSFS_NET:-/sys/class/net}"
    local dev candidates

    candidates="$(ubus call network.interface.wan status 2>/dev/null | jsonfilter -e '@.l3_device' 2>/dev/null)
$(uci -q get network.wan.device 2>/dev/null)
$(uci -q get network.wan.ifname 2>/dev/null)
$(ip route show default 2>/dev/null | awk '/^default/{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i+1); exit }}')"

    for dev in $candidates; do
        [ -n "$dev" ] || continue
        # A bridge/device name from uci can still be a config-only alias.
        [ -e "$sysfs/$dev" ] || continue
        echo "$dev"
        return 0
    done
    return 1
}

tctl_get_lan_device() {
    local dev
    dev=$(uci -q get network.lan.device 2>/dev/null)
    [ -z "$dev" ] && dev=$(uci -q get network.lan.ifname 2>/dev/null)
    [ -z "$dev" ] && dev="br-lan"
    echo "$dev"
}

# Enumerate all LAN-side IPv4 subnets, one per L3 interface.
#
# "LAN" = firewall zones that are NOT internet-facing. A zone is treated as LAN
# if it is named "lan", or if it is neither a wan zone nor masqueraded. This
# deliberately excludes VPN/tunnel zones (e.g. WireGuard/AmneziaWG awg*, which
# carry their own IPv4 and would otherwise be mistaken for LANs) because those
# are masqueraded out. Covers bridges (br-lan), bridge-VLANs and plain VLAN
# interfaces (eth0.20) uniformly via each interface's l3_device.
#
# Output: one line per subnet, "l3_device netbase_int block_size router_int"
# where membership can be tested without awk bit-ops:
#   ip in subnet  <=>  ipint - (ipint % block) == netbase
tctl_lan_subnets() {
    local i=0 zname zmasq nets net st l3 addr mask
    local o1 o2 o3 o4 ipint block netbase
    while zname=$(uci -q get "firewall.@zone[$i].name" 2>/dev/null); [ -n "$zname" ]; do
        zmasq=$(uci -q get "firewall.@zone[$i].masq" 2>/dev/null)
        nets=$(uci -q get "firewall.@zone[$i].network" 2>/dev/null)
        i=$((i + 1))
        case "$zname" in wan|wan6) continue ;; esac
        [ "$zname" != "lan" ] && [ "$zmasq" = "1" ] && continue
        for net in $nets; do
            st=$(ubus call "network.interface.$net" status 2>/dev/null)
            l3=$(echo "$st" | jsonfilter -e '@.l3_device' 2>/dev/null)
            addr=$(echo "$st" | jsonfilter -e '@["ipv4-address"][0].address' 2>/dev/null)
            mask=$(echo "$st" | jsonfilter -e '@["ipv4-address"][0].mask' 2>/dev/null)
            [ -n "$l3" ] && [ -n "$addr" ] && [ -n "$mask" ] || continue
            [ "$mask" -ge 1 ] && [ "$mask" -le 32 ] 2>/dev/null || continue
            o1=${addr%%.*}; rest=${addr#*.}
            o2=${rest%%.*}; rest=${rest#*.}
            o3=${rest%%.*}; o4=${rest##*.}
            ipint=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
            block=$(( 1 << (32 - mask) ))
            netbase=$(( ipint - (ipint % block) ))
            echo "$l3 $netbase $block $ipint"
        done
    done
}

# Concrete devices to attach netdev ingress hooks to.
#
# A netdev ingress hook bound to a BRIDGE never sees bridged traffic: packets
# are received on the bridge's physical ports, so the hook must live there.
# Binding to br-lan silently matches nothing, which is exactly how upload
# limiting appeared to be applied while having no effect. Non-bridge L3
# devices (plain ports, VLAN interfaces) are hooked directly.
tctl_ingress_devices() {
    local sysfs="${TCTL_SYSFS_NET:-/sys/class/net}"
    local dev port
    for dev in $(tctl_get_lan_devices); do
        if [ -d "$sysfs/$dev/brif" ]; then
            for port in "$sysfs/$dev/brif/"*; do
                [ -e "$port" ] || continue
                basename "$port"
            done
        else
            echo "$dev"
        fi
    done | sort -u
}

# nft chain name for a device's ingress hook (chain names can't contain
# dots or dashes, which interface names routinely do).
tctl_ingress_chain() {
    printf 'ul_%s' "$(printf '%s' "$1" | tr -c 'a-zA-Z0-9' '_')"
}

# LAN L3 device names only (deduplicated), e.g. "br-lan br-guest eth0.20".
tctl_get_lan_devices() {
    tctl_lan_subnets | awk '{print $1}' | sort -u
}

# Convert "a.b.c.d/m" (or a bare host address) to "netbase_int block_size",
# normalized to the network base. Fails silently on malformed input.
tctl_cidr_spec() {
    local cidr="$1" addr mask rest o1 o2 o3 o4 ipint block
    addr=${cidr%%/*}
    mask=${cidr#*/}
    [ "$mask" = "$cidr" ] && mask=32
    tctl_validate_ip "$addr" || return 1
    case "$mask" in ''|*[!0-9]*) return 1 ;; esac
    [ "$mask" -ge 1 ] && [ "$mask" -le 32 ] || return 1
    o1=${addr%%.*}; rest=${addr#*.}
    o2=${rest%%.*}; rest=${rest#*.}
    o3=${rest%%.*}; o4=${rest##*.}
    ipint=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
    block=$(( 1 << (32 - mask) ))
    echo "$(( ipint - (ipint % block) )) $block"
}

# Downstream subnets routed via a next-hop on a LAN interface — e.g. clients
# behind a second router on the LAN whose packets are forwarded (and NATed on
# WAN) through this router with their original source addresses. Also includes
# operator-defined extras from trafficctl.main.extra_subnets (space-separated
# CIDRs) for setups without an explicit kernel route.
# Output format matches tctl_lan_subnets; router_int is 0 because no local
# address lives inside a routed subnet (consumers use 0 to tell routed from
# directly connected).
tctl_routed_subnets() {
    local lan_devs dev cidr spec extras
    lan_devs=$(tctl_get_lan_devices)

    if [ -n "$lan_devs" ]; then
        ip route show 2>/dev/null | awk '
        $1 != "default" && / via / {
            dev = ""
            for (i = 1; i <= NF; i++) if ($i == "dev") dev = $(i+1)
            if (dev != "") print $1, dev
        }' | while read -r cidr dev; do
            echo "$lan_devs" | grep -qxF "$dev" || continue
            spec=$(tctl_cidr_spec "$cidr") || continue
            echo "$dev $spec 0"
        done
    fi

    extras=$(uci -q get trafficctl.main.extra_subnets 2>/dev/null)
    if [ -n "$extras" ]; then
        dev=$(tctl_get_lan_device)
        for cidr in $extras; do
            spec=$(tctl_cidr_spec "$cidr") || continue
            echo "$dev $spec 0"
        done
    fi
}

# Every subnet worth monitoring: directly connected LANs first, then routed
# and extra ones. Duplicate prefixes are dropped (first wins, keeping the
# connected entry with its real router address).
tctl_monitored_subnets() {
    { tctl_lan_subnets; tctl_routed_subnets; } | awk '!seen[$2":"$3]++'
}

# True (0) when the IP belongs to a directly connected LAN subnet; routed and
# extra subnets do not count. Used to tell on-link devices from downstream
# ones that only have an L3 presence here.
tctl_ip_in_lan() {
    local ip="$1" o1 o2 o3 o4 rest ipint
    tctl_validate_ip "$ip" || return 1
    o1=${ip%%.*}; rest=${ip#*.}
    o2=${rest%%.*}; rest=${rest#*.}
    o3=${rest%%.*}; o4=${rest##*.}
    ipint=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
    tctl_lan_subnets | awk -v si="$ipint" '
        si - (si % $3) == $2 { hit = 1; exit }
        END { exit hit ? 0 : 1 }'
}

# Accept a single host address or a CIDR block ("all" means every address).
# Echoes the normalized target, or fails.
tctl_validate_target() {
    local t="$1" addr mask
    case "$t" in
        all|any) echo "0.0.0.0/0"; return 0 ;;
    esac
    case "$t" in
        */*)
            addr=${t%%/*}
            mask=${t#*/}
            tctl_validate_ip "$addr" || return 1
            case "$mask" in ''|*[!0-9]*) return 1 ;; esac
            [ "$mask" -ge 0 ] && [ "$mask" -le 32 ] || return 1
            echo "$addr/$mask"
            ;;
        *)
            tctl_validate_ip "$t" || return 1
            echo "$t"
            ;;
    esac
}

# A target usable inside an nft set/meter name or a rule comment.
tctl_target_slug() {
    printf '%s' "$1" | tr './' '__'
}

tctl_validate_ip() {
    echo "$1" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' || return 1
    local IFS='.'
    # shellcheck disable=SC2086
    set -- $1
    [ "$1" -le 255 ] && [ "$2" -le 255 ] && [ "$3" -le 255 ] && [ "$4" -le 255 ] 2>/dev/null
}

tctl_get_wifi_interfaces() {
    uci show wireless 2>/dev/null | grep '=wifi-iface' | cut -d. -f2 | cut -d= -f1
}

# Get running WiFi interface names (e.g. wlan0, wlan1)
tctl_get_hostapd_ifaces() {
    ubus list 2>/dev/null | grep '^hostapd\.' | cut -d. -f2
}

# Add MAC to hostapd deny ACL at runtime + deauth the client (no wifi reload)
tctl_hostapd_deny_mac() {
    local mac="$1"
    local iface
    for iface in $(tctl_get_hostapd_ifaces); do
        hostapd_cli -i "$iface" deny_acl ADD_MAC "$mac" 2>/dev/null
        hostapd_cli -i "$iface" deauthenticate "$mac" 2>/dev/null
    done
}

# Remove MAC from hostapd deny ACL at runtime (client can reassociate immediately)
tctl_hostapd_allow_mac() {
    local mac="$1"
    local iface
    for iface in $(tctl_get_hostapd_ifaces); do
        hostapd_cli -i "$iface" deny_acl DEL_MAC "$mac" 2>/dev/null
    done
}

# ── Persistence ───────────────────────────────────────────────────────────

TCTL_RULES_FILE="/etc/trafficctl/rules.json"

tctl_persist_enabled() {
    [ "$(uci -q get trafficctl.main.persist_rules 2>/dev/null)" = "1" ]
}

tctl_persist_save() {
    local type="$1" ip="$2" param="$3"
    [ -d "$(dirname "$TCTL_RULES_FILE")" ] || mkdir -p "$(dirname "$TCTL_RULES_FILE")"
    [ -f "$TCTL_RULES_FILE" ] || echo '[]' > "$TCTL_RULES_FILE"
    local tmp="${TCTL_RULES_FILE}.tmp"
    # Remove existing entry for same ip+type, append new one
    awk -v ip="$ip" -v t="$type" -v p="$param" '
    {
        gsub(/^\[/,""); gsub(/\]$/,"")
        n=split($0, items, "},{")
        printf "["
        first=1
        for (i=1; i<=n; i++) {
            sub(/^\{/,"",items[i]); sub(/\}$/,"",items[i])
            if (items[i] ~ "\"ip\":\"" ip "\"" && items[i] ~ "\"type\":\"" t "\"") continue
            if (!first) printf ","
            printf "{%s}", items[i]
            first=0
        }
        if (!first) printf ","
        printf "{\"type\":\"%s\",\"ip\":\"%s\",\"param\":\"%s\"}]", t, ip, p
    }' "$TCTL_RULES_FILE" > "$tmp"
    mv "$tmp" "$TCTL_RULES_FILE"
}

tctl_persist_remove() {
    local type="$1" ip="$2"
    [ -f "$TCTL_RULES_FILE" ] || return 0
    local tmp="${TCTL_RULES_FILE}.tmp"
    awk -v ip="$ip" -v t="$type" '
    {
        gsub(/^\[/,""); gsub(/\]$/,"")
        n=split($0, items, "},{")
        printf "["
        first=1
        for (i=1; i<=n; i++) {
            sub(/^\{/,"",items[i]); sub(/\}$/,"",items[i])
            if (items[i] ~ "\"ip\":\"" ip "\"" && items[i] ~ "\"type\":\"" t "\"") continue
            if (!first) printf ","
            printf "{%s}", items[i]
            first=0
        }
        printf "]"
    }' "$TCTL_RULES_FILE" > "$tmp"
    mv "$tmp" "$TCTL_RULES_FILE"
}

# ── Activity Logging ──────────────────────────────────────────────────────

TCTL_LOG_TAG="trafficctl"

tctl_log_enabled() {
    [ "$(uci -q get trafficctl.logging.enabled 2>/dev/null)" = "1" ]
}

tctl_log_category_enabled() {
    local cat="$1"
    [ "$(uci -q get "trafficctl.logging.log_${cat}" 2>/dev/null)" != "0" ]
}

tctl_log() {
    local action="$1" target="$2" detail="$3" via="${4:-cli}" src="${5:-local}"
    tctl_log_enabled || return 0

    local category
    case "$action" in
        block|unblock) category="blocks" ;;
        ratelimit*) category="ratelimits" ;;
        shape*) category="shapes" ;;
        telegram*) category="telegram" ;;
        config*) category="config" ;;
        *) category="config" ;;
    esac
    tctl_log_category_enabled "$category" || return 0

    local ts user log_file max_lines
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    user="${TCTL_USER:-$(id -un 2>/dev/null || echo unknown)}"
    log_file=$(uci -q get trafficctl.logging.log_file 2>/dev/null)
    log_file="${log_file:-/tmp/trafficctl/activity.log}"
    max_lines=$(uci -q get trafficctl.logging.max_lines 2>/dev/null)
    max_lines="${max_lines:-500}"

    local entry="[$TCTL_LOG_TAG] $ts src=$src user=$user via=$via action=$action target=$target${detail:+ detail=$detail}"

    [ -d "$(dirname "$log_file")" ] || mkdir -p "$(dirname "$log_file")"
    echo "$entry" >> "$log_file"

    # Rotate if over max_lines
    local lc
    lc=$(wc -l < "$log_file" 2>/dev/null || echo 0)
    if [ "$lc" -gt "$max_lines" ]; then
        local keep=$(( max_lines * 3 / 5 ))
        tail -n "$keep" "$log_file" > "${log_file}.tmp"
        mv "${log_file}.tmp" "$log_file"
    fi

    # Duplicate to syslog if configured
    if [ "$(uci -q get trafficctl.logging.syslog 2>/dev/null)" = "1" ]; then
        logger -t "$TCTL_LOG_TAG" "$ts src=$src user=$user via=$via action=$action target=$target${detail:+ detail=$detail}"
    fi
}

# ── Flow Offload Detection ─────────────────────────────────────────────────

tctl_get_offload_mode() {
    local sw hw
    sw=$(uci -q get firewall.@defaults[0].flow_offloading 2>/dev/null)
    hw=$(uci -q get firewall.@defaults[0].flow_offloading_hw 2>/dev/null)
    if [ "$hw" = "1" ]; then
        # kernel 5.7+ supports counter sync on flowtables (docs.kernel.org/networking/nf_flowtable.html).
        # OpenWrt 22.03+ fw4 sets the counter flag by default, syncing hardware
        # byte counts back to conntrack — monitoring works.
        if nft list flowtables 2>/dev/null | grep -q "counter"; then
            echo "hardware-counter"
        else
            echo "hardware"
        fi
    elif [ "$sw" = "1" ]; then
        echo "software"
    else
        echo "none"
    fi
}
