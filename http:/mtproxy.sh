#!/bin/bash
set -e

SERVICE_FILE="/etc/systemd/system/mtproxy.service"
INSTALL_DIR="/opt/mtproxy"
BINARY="$INSTALL_DIR/mtproto-proxy"

function install_mtproxy() {
    clear
    echo "=== MTProxy Installation ==="

    PORT=9999

    read -p "Port: " HVAL
    if ! [[ $HVAL =~ ^[0-9]+$ ]]; then
        echo "Invalid value."
        exit 1
    fi

    read -p "Secret (leave empty to auto-generate): " SECRET
    if [[ -z "$SECRET" ]]; then
        SECRET=$(hexdump -vn "16" -e ' /1 "%02x"' /dev/urandom)
    else
        SECRET=$(echo "$SECRET" | tr 'A-Z' 'a-z')
        if ! [[ $SECRET =~ ^[0-9a-f]{32}$ ]]; then
            echo "Invalid secret."
            exit 1
        fi
    fi

    read -p "TAG: " TAG
    read -p "TLS domain: " TLS_DOMAIN

    read -p "Workers: " WORKERS
    if ! [[ $WORKERS =~ ^[0-9]+$ ]]; then
        echo "Invalid value."
        exit 1
    fi

    echo "Installing..."
    sleep 1

    apt update
    apt install -y git curl build-essential libssl-dev zlib1g-dev libcap2-bin

    # FIX: Always remove old source folder to avoid git clone errors
    rm -rf MTProxy

    git clone https://github.com/hesiadmin-maker/MTProxy
    cd MTProxy
    make
    cd objs/bin

    curl -s https://core.telegram.org/getProxySecret -o proxy-secret
    curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf

    id mtproxy &>/dev/null || useradd -r -s /usr/sbin/nologin mtproxy

    mkdir -p $INSTALL_DIR
    cp mtproto-proxy proxy-secret proxy-multi.conf $INSTALL_DIR
    chown -R mtproxy:mtproxy $INSTALL_DIR
    chmod 750 $INSTALL_DIR

    setcap 'cap_net_bind_service=+ep' $BINARY

    if ! grep -q "^mtproxy soft nofile" /etc/security/limits.conf; then
cat >> /etc/security/limits.conf <<EOF
mtproxy soft nofile 300000
mtproxy hard nofile 300000
EOF
    fi

    sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=300000/' /etc/systemd/system.conf
    sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=300000/' /etc/systemd/user.conf

cat > $SERVICE_FILE <<EOF
[Unit]
Description=MTProto Proxy Service (Hardened)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mtproxy
Group=mtproxy
WorkingDirectory=$INSTALL_DIR

ExecStart=$BINARY \\
  -p $PORT \\
  -H $HVAL \\
  -S $SECRET \\
  --http-stats \\
  --aes-pwd proxy-secret proxy-multi.conf \\
  -P $TAG \\
  -M $WORKERS \\
  -D $TLS_DOMAIN \\
  -Z 1-12

Restart=always
RestartSec=2

CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
SecureBits=keep-caps

LimitNOFILE=300000
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

RestrictAddressFamilies=AF_INET AF_INET6

SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

ReadOnlyPaths=$INSTALL_DIR
ReadWritePaths=$INSTALL_DIR/proxy-secret $INSTALL_DIR/proxy-multi.conf

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable mtproxy
    systemctl restart mtproxy

    echo "Installation complete."
}

function show_status() {
    clear
    systemctl status mtproxy --no-pager
}

function restart_service() {
    systemctl restart mtproxy
    echo "Service restarted."
}

function stop_service() {
    systemctl stop mtproxy
    echo "Service stopped."
}

function uninstall_mtproxy() {
    systemctl stop mtproxy
    systemctl disable mtproxy
    rm -f $SERVICE_FILE
    rm -rf $INSTALL_DIR
    systemctl daemon-reload
    echo "MTProxy uninstalled."
}

function full_remove_mtproxy() {
    echo "Removing MTProxy source folder..."
    rm -rf MTProxy
    echo "Source folder removed."
}

# ===========================
#  MENU
# ===========================

while true; do
    clear
    echo "=============================="
    echo "        MTProxy Manager"
    echo "=============================="
    echo "1) Install MTProxy"
    echo "2) Service Status"
    echo "3) Restart Service"
    echo "4) Stop Service"
    echo "5) Uninstall MTProxy"
    echo "6) Full Remove (rm -rf MTProxy)"
    echo "0) Exit"
    echo "=============================="
    read -p "Select: " opt

    case $opt in
        1) install_mtproxy ;;
        2) show_status ;;
        3) restart_service ;;
        4) stop_service ;;
        5) uninstall_mtproxy ;;
        6) full_remove_mtproxy ;;
        0) exit ;;
        *) echo "Invalid option" ;;
    esac

    read -p "Press Enter to continue..."
done
