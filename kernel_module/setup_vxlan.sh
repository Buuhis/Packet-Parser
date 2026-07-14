#!/bin/bash

# --- SYSTEM CONFIGURATION ---
# Target network definitions for the 2 paths
# Path 1 (enp8s0) links 100.64.1.2 and 100.64.2.2
PATH1_IP_A="100.64.1.2"
PATH1_IP_B="100.64.2.2"
VX1_DEV="enp8s0"
VX1_NAME="ne_tunnel1"
VX1_ID=1234
VX1_PORT=65001

# Path 2 (enp9s0) links 100.64.11.2 and 100.64.22.2
PATH2_IP_A="100.64.11.2"
PATH2_IP_B="100.64.22.2"
VX2_DEV="enp9s0"
VX2_NAME="ne_tunnel2"
VX2_ID=1235
VX2_PORT=65002

# --- AUTOMATIC SERVER DETECTION ---
if ip addr show dev "$VX1_DEV" 2>/dev/null | grep -q "$PATH1_IP_A"; then
    SERVER_ROLE="SERVER_1"
    
    VX1_LOCAL="$PATH1_IP_A";  VX1_REMOTE="$PATH1_IP_B"
    VX2_LOCAL="$PATH2_IP_A";  VX2_REMOTE="$PATH2_IP_B"
    
    VX1_IP="172.16.23.1/24"
    VX2_IP="172.16.25.1/24"
    PEER_GW="172.16.23.2"
    
    VX1_MAC="02:00:00:01:23:01"
    VX2_MAC="02:00:00:00:25:01"
    
    VX1_PEER_MAC="02:00:00:00:23:02"
    VX2_PEER_MAC="02:00:00:00:25:02"
    
    MS1_CAK="00112233445566778899aabbccddeeff"
    MS2_CAK="aabbccddeeff00112233445566778899"
    
elif ip addr show dev "$VX1_DEV" 2>/dev/null | grep -q "$PATH1_IP_B"; then
    SERVER_ROLE="SERVER_2"
    
    VX1_LOCAL="$PATH1_IP_B";  VX1_REMOTE="$PATH1_IP_A"
    VX2_LOCAL="$PATH2_IP_B";  VX2_REMOTE="$PATH2_IP_A"
    
    VX1_IP="172.16.23.2/24"  
    VX2_IP="172.16.25.2/24"  
    PEER_GW="172.16.23.1"
    
    VX1_MAC="02:00:00:00:23:02"
    VX2_MAC="02:00:00:00:25:02"
    
    VX1_PEER_MAC="02:00:00:01:23:01"
    VX2_PEER_MAC="02:00:00:00:25:01"
    
    MS1_CAK="00112233445566778899aabbccddeeff"
    MS2_CAK="aabbccddeeff00112233445566778899"
else
    echo -e "\e[1;31m[ERROR]\e[0m Could not detect Server identity based on $VX1_DEV IP address."
    exit 1
fi

# --- HELPER FUNCTIONS ---
log() { echo -e "\e[1;32m[INFO]\e[0m $1"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $1"; }

start_vxlan() {
    log "Detected Identity: \e[1;36m$SERVER_ROLE\e[0m"
    log "Initializing VXLAN tunnels (Raw)..."

    # Clean up first
    stop_vxlan

    # Tunnel 1
    ip link add "$VX1_NAME" type vxlan id $VX1_ID dev $VX1_DEV local $VX1_LOCAL remote $VX1_REMOTE dstport $VX1_PORT
    bridge fdb append to 00:00:00:00:00:00 dst "$VX1_REMOTE" dev "$VX1_NAME"
    ip link set "$VX1_NAME" up
    ip addr add "$VX1_IP" dev "$VX1_NAME"
    log "Successfully created raw $VX1_NAME (Local: $VX1_LOCAL -> Remote: $VX1_REMOTE)"

    # Tunnel 2
    ip link add "$VX2_NAME" type vxlan id $VX2_ID dev $VX2_DEV local $VX2_LOCAL remote $VX2_REMOTE dstport $VX2_PORT
    bridge fdb append to 00:00:00:00:00:00 dst "$VX2_REMOTE" dev "$VX2_NAME"
    ip link set "$VX2_NAME" up
    ip addr add "$VX2_IP" dev "$VX2_NAME"
    log "Successfully created raw $VX2_NAME (Local: $VX2_LOCAL -> Remote: $VX2_REMOTE)"

    # Configure routing automatically
    if [ "$SERVER_ROLE" = "SERVER_1" ]; then
        PEER_SUBNET="192.168.182.0/24"
    else
        PEER_SUBNET="192.168.9.0/24"
    fi
    ip route replace "$PEER_SUBNET" via "$PEER_GW" dev "$VX1_NAME"
    log "Added route: $PEER_SUBNET via $PEER_GW dev $VX1_NAME"
}

start_macsec() {
    log "Detected Identity: \e[1;36m$SERVER_ROLE\e[0m"
    log "Configuring MACsec security over VXLAN (Enable Secure Tunnel)..."

    # Clean up first to ensure clean state
    stop_vxlan

    # --- Tunnel 1 ---
    # Configure VXLAN parent (l2tun1)
    ip link add l2tun1 type vxlan id $VX1_ID dev $VX1_DEV local $VX1_LOCAL remote $VX1_REMOTE dstport $VX1_PORT
    ip link set l2tun1 address "$VX1_MAC"
    bridge fdb append to 00:00:00:00:00:00 dst "$VX1_REMOTE" dev l2tun1
    ip link set l2tun1 up

    # Configure MACsec (ne_tunnel1) on top of l2tun1
    ip link add link l2tun1 name "$VX1_NAME" type macsec port 1 encrypt on replay on window 64 cipher gcm-aes-128
    ip macsec add "$VX1_NAME" tx sa 0 xpn 1 on key 01 "$MS1_CAK"
    ip macsec add "$VX1_NAME" rx address "$VX1_PEER_MAC" port 1
    ip macsec add "$VX1_NAME" rx address "$VX1_PEER_MAC" port 1 sa 0 xpn 1 on key 01 "$MS1_CAK"
    ip link set "$VX1_NAME" up
    ip addr add "$VX1_IP" dev "$VX1_NAME"
    log "Successfully created MACsec $VX1_NAME stacked on l2tun1"

    # --- Tunnel 2 ---
    # Configure VXLAN parent (l2tun2)
    ip link add l2tun2 type vxlan id $VX2_ID dev $VX2_DEV local $VX2_LOCAL remote $VX2_REMOTE dstport $VX2_PORT
    ip link set l2tun2 address "$VX2_MAC"
    bridge fdb append to 00:00:00:00:00:00 dst "$VX2_REMOTE" dev l2tun2
    ip link set l2tun2 up

    # Configure MACsec (ne_tunnel2) on top of l2tun2
    ip link add link l2tun2 name "$VX2_NAME" type macsec port 2 encrypt on replay on window 64 cipher gcm-aes-128
    ip macsec add "$VX2_NAME" tx sa 0 xpn 1 on key 01 "$MS2_CAK"
    ip macsec add "$VX2_NAME" rx address "$VX2_PEER_MAC" port 2
    ip macsec add "$VX2_NAME" rx address "$VX2_PEER_MAC" port 2 sa 0 xpn 1 on key 01 "$MS2_CAK"
    ip link set "$VX2_NAME" up
    ip addr add "$VX2_IP" dev "$VX2_NAME"
    log "Successfully created MACsec $VX2_NAME stacked on l2tun2"

    # Configure routing automatically
    if [ "$SERVER_ROLE" = "SERVER_1" ]; then
        PEER_SUBNET="192.168.182.0/24"
    else
        PEER_SUBNET="192.168.9.0/24"
    fi
    ip route replace "$PEER_SUBNET" via "$PEER_GW" dev "$VX1_NAME"
    log "Added route: $PEER_SUBNET via $PEER_GW dev $VX1_NAME"
}

stop_vxlan() {
    log "Tearing down network configuration..."
    
    [ -d "/sys/class/net/ne_tunnel1" ] && ip link del ne_tunnel1 && log "Deleted ne_tunnel1"
    [ -d "/sys/class/net/ne_tunnel2" ] && ip link del ne_tunnel2 && log "Deleted ne_tunnel2"
    [ -d "/sys/class/net/l2tun1" ] && ip link del l2tun1 && log "Deleted l2tun1"
    [ -d "/sys/class/net/l2tun2" ] && ip link del l2tun2 && log "Deleted l2tun2"
}

# --- ACTION ROUTER ---
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run this script as root (sudo)."
    exit 1
fi

case "$1" in
    start)       start_vxlan ;;
    stop)        stop_vxlan ;;
    macsec-on)   start_macsec ;;
    macsec-off)  start_vxlan ;;
    restart)     stop_vxlan; start_vxlan ;;
    *)
        echo "Usage: $0 {start|stop|macsec-on|macsec-off|restart}"
        echo "----------------------------------------------------------------"
        echo "  start      : Set up raw VXLAN tunnels (active devs: ne_tunnel1/2)"
        echo "  stop       : Delete all VXLAN and MACsec interfaces"
        echo "  macsec-on  : Enable MACsec (active devs: ne_tunnel1/2 stacked on l2tun1/2)"
        echo "  macsec-off : Disable MACsec (reverts active devs to raw ne_tunnel1/2)"
        exit 1
        ;;
esac

exit 0