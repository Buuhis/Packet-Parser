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
# Check which IP is assigned locally to determine if we are Server 1 or Server 2
if ip addr show dev "$VX1_DEV" 2>/dev/null | grep -q "$PATH1_IP_A"; then
    SERVER_ROLE="SERVER_1"
    
    VX1_LOCAL="$PATH1_IP_A";  VX1_REMOTE="$PATH1_IP_B"
    VX2_LOCAL="$PATH2_IP_A";  VX2_REMOTE="$PATH2_IP_B"
    
    # Separated Overlay Subnets to prevent routing conflict
    VX1_IP="172.16.25.1/24"
    VX2_IP="172.16.25.3/24"
    
    # Custom Unique MAC Addresses for Server 1
    VX1_MAC="02:00:00:00:23:01"
    VX2_MAC="02:00:00:00:25:01"
    
    # MACsec Config for Server 1
    MS1_NAME="ms_tunnel1"; MS2_NAME="ms_tunnel2"
    MS1_CAK="00112233445566778899aabbccddeeff"; MS1_CKN="112233445566778899aabbccddeeff00"
    MS2_CAK="aabbccddeeff00112233445566778899"; MS2_CKN="eeddccbbaa99887766554433221100ff"
    
elif ip addr show dev "$VX1_DEV" 2>/dev/null | grep -q "$PATH1_IP_B"; then
    SERVER_ROLE="SERVER_2"
    
    VX1_LOCAL="$PATH1_IP_B";  VX1_REMOTE="$PATH1_IP_A"
    VX2_LOCAL="$PATH2_IP_B";  VX2_REMOTE="$PATH2_IP_A"
    
    # Separated Overlay Subnets to prevent routing conflict
    VX1_IP="172.16.25.2/24"  
    VX2_IP="172.16.25.4/24"  
    
    # Custom Unique MAC Addresses for Server 2
    VX1_MAC="02:00:00:00:23:02"
    VX2_MAC="02:00:00:00:25:02"
    
    # MACsec Config for Server 2 (Keys match Server 1)
    MS1_NAME="ms_tunnel1"; MS2_NAME="ms_tunnel2"
    MS1_CAK="00112233445566778899aabbccddeeff"; MS1_CKN="112233445566778899aabbccddeeff00"
    MS2_CAK="aabbccddeeff00112233445566778899"; MS2_CKN="eeddccbbaa99887766554433221100ff"
else
    echo -e "\e[1;31m[ERROR]\e[0m Could not detect Server identity based on $VX1_DEV IP address."
    echo "Please ensure interface $VX1_DEV is up and has either $PATH1_IP_A or $PATH1_IP_B assigned."
    exit 1
fi

# --- HELPER FUNCTIONS ---
log() { echo -e "\e[1;32m[INFO]\e[0m $1"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $1"; }

start_vxlan() {
    log "Detected Identity: \e[1;36m$SERVER_ROLE\e[0m"
    log "Initializing VXLAN tunnels..."

    # Tunnel 1
    if ! ip link show "$VX1_NAME" >/dev/null 2>&1; then
        # FIXED: Placed 'address' and 'mtu' BEFORE 'type vxlan'
        ip link add "$VX1_NAME" address "$VX1_MAC" mtu 1450 type vxlan id $VX1_ID remote $VX1_REMOTE local $VX1_LOCAL dev $VX1_DEV dstport $VX1_PORT
        ip addr add $VX1_IP dev "$VX1_NAME"
        ip link set "$VX1_NAME" up
        log "Successfully created $VX1_NAME (MAC: $VX1_MAC | Local: $VX1_LOCAL -> Remote: $VX1_REMOTE)"
    else
        warn "$VX1_NAME already exists."
    fi

    # Tunnel 2
    if ! ip link show "$VX2_NAME" >/dev/null 2>&1; then
        # FIXED: Placed 'address' and 'mtu' BEFORE 'type vxlan'
        ip link add "$VX2_NAME" address "$VX2_MAC" mtu 1450 type vxlan id $VX2_ID remote $VX2_REMOTE local $VX2_LOCAL dev $VX2_DEV dstport $VX2_PORT
        ip addr add $VX2_IP dev "$VX2_NAME"
        ip link set "$VX2_NAME" up
        log "Successfully created $VX2_NAME (MAC: $VX2_MAC | Local: $VX2_LOCAL -> Remote: $VX2_REMOTE)"
    else
        warn "$VX2_NAME already exists."
    fi
}

stop_vxlan() {
    log "Tearing down network configuration..."
    stop_macsec
    [ -d "/sys/class/net/$VX1_NAME" ] && ip link del "$VX1_NAME" && log "Deleted $VX1_NAME"
    [ -d "/sys/class/net/$VX2_NAME" ] && ip link del "$VX2_NAME" && log "Deleted $VX2_NAME"
}

start_macsec() {
    log "Configuring MACsec security over VXLAN for $SERVER_ROLE..."

    if [ ! -d "/sys/class/net/$VX1_NAME" ] || [ ! -d "/sys/class/net/$VX2_NAME" ]; then
        warn "VXLAN interfaces are not found. Please run 'start' action first."
        exit 1
    fi

    # MACsec Tunnel 1
    if ! ip link show "$MS1_NAME" >/dev/null 2>&1; then
        ip link add link "$VX1_NAME" "$MS1_NAME" type macsec
        ip macsec add "$MS1_NAME" tx sa 0 pn 1 on key "$MS1_CKN" "$MS1_CAK"
        ip macsec add "$MS1_NAME" rx port 1 address "$VX1_REMOTE"
        ip macsec add "$MS1_NAME" rx port 1 sa 0 pn 1 on key "$MS1_CKN" "$MS1_CAK"
        ip link set "$MS1_NAME" up
        log "MACsec enabled on $VX1_NAME -> Device: $MS1_NAME"
    else
        warn "MACsec on $VX1_NAME ($MS1_NAME) is already configured."
    fi

    # MACsec Tunnel 2
    if ! ip link show "$MS2_NAME" >/dev/null 2>&1; then
        ip link add link "$VX2_NAME" "$MS2_NAME" type macsec
        ip macsec add "$MS2_NAME" tx sa 0 pn 1 on key "$MS2_CKN" "$MS2_CAK"
        ip macsec add "$MS2_NAME" rx port 1 address "$VX2_REMOTE"
        ip macsec add "$MS2_NAME" rx port 1 sa 0 pn 1 on key "$MS2_CKN" "$MS2_CAK"
        ip link set "$MS2_NAME" up
        log "MACsec enabled on $VX2_NAME -> Device: $MS2_NAME"
    else
        warn "MACsec on $VX2_NAME ($MS2_NAME) is already configured."
    fi
}

stop_macsec() {
    log "Removing MACsec security layer..."
    [ -d "/sys/class/net/$MS1_NAME" ] && ip link del "$MS1_NAME" && log "Removed MACsec: $MS1_NAME"
    [ -d "/sys/class/net/$MS2_NAME" ] && ip link del "$MS2_NAME" && log "Removed MACsec: $MS2_NAME"
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
    macsec-off)  stop_macsec ;;
    restart)     stop_vxlan; start_vxlan ;;
    *)
        echo "Usage: $0 {start|stop|macsec-on|macsec-off|restart}"
        echo "----------------------------------------------------------------"
        echo "  start      : Automatically detects host role and sets up VXLAN"
        echo "  stop       : Delete both VXLAN & MACsec"
        echo "  macsec-on  : Enable MACsec overlay on top of VXLAN"
        echo "  macsec-off : Disable MACsec layer (Keep raw VXLAN tunnels)"
        exit 1
        ;;
esac

exit 0