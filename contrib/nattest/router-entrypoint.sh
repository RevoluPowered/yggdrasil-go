#!/bin/sh
set -e

# Identify WAN and LAN interfaces by subnet prefix from env vars
WAN=""
LAN=""

# List all interfaces except lo
for iface in $(ls /sys/class/net/ | grep -v lo); do
    addr=$(ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]}')
    [ -z "$addr" ] && continue
    case "$addr" in
        ${WAN_SUBNET}*) WAN="$iface" ;;
        ${LAN_SUBNET}*) LAN="$iface" ;;
    esac
done

echo "NAT_TYPE=$NAT_TYPE WAN=$WAN LAN=$LAN"

if [ -z "$WAN" ] || [ -z "$LAN" ]; then
    echo "ERROR: Could not identify WAN ($WAN_SUBNET) or LAN ($LAN_SUBNET) interface"
    echo "Interfaces:"
    for iface in $(ls /sys/class/net/); do
        addr=$(ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]}')
        echo "  $iface: $addr"
    done
    exit 1
fi

case "$NAT_TYPE" in
    cone)
        iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE
        iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
        iptables -A FORWARD -i "$WAN" -o "$LAN" -j ACCEPT
        echo "Cone NAT configured"
        ;;
    symmetric)
        iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE --random
        iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
        iptables -A FORWARD -i "$WAN" -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT
        echo "Symmetric NAT configured"
        ;;
    udpblock)
        iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE
        iptables -A FORWARD -p udp --dport 53 -j ACCEPT
        iptables -A FORWARD -p udp --sport 53 -j ACCEPT
        iptables -A FORWARD -p udp -j DROP
        iptables -A FORWARD -i "$LAN" -o "$WAN" -p tcp -j ACCEPT
        iptables -A FORWARD -i "$WAN" -o "$LAN" -p tcp -m state --state RELATED,ESTABLISHED -j ACCEPT
        echo "UDP-blocked NAT configured"
        ;;
    *)
        echo "Unknown NAT_TYPE: $NAT_TYPE"
        exit 1
        ;;
esac

echo "Router ready, sleeping..."
exec sleep infinity
