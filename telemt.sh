#!/bin/bash
set -e

SERVICE_FILE="/etc/systemd/system/telemt.service"
CONFIG_DIR="/etc/telemt"
CONFIG_FILE="$CONFIG_DIR/telemt.toml"
TELEMT_BIN="/usr/local/bin/telemt"
REPO="telemt/telemt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
print_title() { echo -e "${BLUE}══════════════════════════════════════════${NC}"; }

show_menu() {
    clear
    print_title
    echo -e "${BLUE}       Telemt MTProxy Auto Installer${NC}"
    print_title
    echo ""
    echo "1) Install MTProxy (Telemt)"
    echo "2) Show Service Status"
    echo "3) Restart Service"
    echo "4) Stop Service"
    echo "5) Uninstall MTProxy"
    echo "6) Show Connection Link"
    echo "7) Add/Update Ad Tag"
    echo "0) Exit"
    print_title
}

detect_arch() {
    sys_arch="$(uname -m)"
    case "$sys_arch" in
        x86_64|amd64)
            if grep -q "avx2" /proc/cpuinfo 2>/dev/null && grep -q "bmi2" /proc/cpuinfo 2>/dev/null; then
                echo "x86_64-v3"
            else
                echo "x86_64"
            fi
            ;;
        aarch64|arm64) echo "aarch64" ;;
        *) echo "unsupported" ;;
    esac
}

detect_libc() {
    if ldd --version 2>&1 | grep -qi musl; then
        echo "musl"
    else
        echo "gnu"
    fi
}

download_binary() {
    local version="$1"
    local arch="$(detect_arch)"
    local libc="$(detect_libc)"
    local file_name="telemt-${arch}-linux-${libc}.tar.gz"
    local temp_dir="$(mktemp -d)"
    
    if [ "$version" = "latest" ]; then
        local url="https://github.com/${REPO}/releases/latest/download/${file_name}"
    else
        local url="https://github.com/${REPO}/releases/download/${version}/${file_name}"
    fi
    
    print_info "Downloading from: $url"
    
    if ! curl -fsSL "$url" -o "${temp_dir}/${file_name}"; then
        # Fallback to standard x86_64
        if [ "$arch" = "x86_64-v3" ]; then
            print_warn "Falling back to standard x86_64 build..."
            arch="x86_64"
            file_name="telemt-${arch}-linux-${libc}.tar.gz"
            if [ "$version" = "latest" ]; then
                url="https://github.com/${REPO}/releases/latest/download/${file_name}"
            else
                url="https://github.com/${REPO}/releases/download/${version}/${file_name}"
            fi
            curl -fsSL "$url" -o "${temp_dir}/${file_name}" || {
                print_error "Download failed"
                rm -rf "$temp_dir"
                return 1
            }
        else
            print_error "Download failed"
            rm -rf "$temp_dir"
            return 1
        fi
    fi
    
    print_info "Extracting archive..."
    tar -xzf "${temp_dir}/${file_name}" -C "$temp_dir"
    
    local binary="$(find "$temp_dir" -type f -name "telemt" 2>/dev/null | head -n 1)"
    if [ -z "$binary" ]; then
        print_error "Binary not found in archive"
        rm -rf "$temp_dir"
        return 1
    fi
    
    cp "$binary" "$TELEMT_BIN"
    chmod +x "$TELEMT_BIN"
    rm -rf "$temp_dir"
    print_info "Binary installed successfully"
    return 0
}

install_telemt() {
    clear
    echo -e "${BLUE}══════════════════════════════════════════${NC}"
    echo -e "${BLUE}         Installation Wizard${NC}"
    echo -e "${BLUE}══════════════════════════════════════════${NC}"
    echo ""

    # Port
    read -p "Enter port [default: 443]: " PORT
    PORT=${PORT:-443}
    
    # TLS Domain
    echo ""
    read -p "Enter Fake TLS domain (e.g., www.google.com): " TLS_DOMAIN
    while [[ -z "$TLS_DOMAIN" ]]; do
        print_error "TLS domain is required"
        read -p "Enter Fake TLS domain: " TLS_DOMAIN
    done
    
    # Secret
    echo ""
    read -p "Enter secret (leave empty to auto-generate): " SECRET
    if [[ -z "$SECRET" ]]; then
        SECRET=$(openssl rand -hex 16)
        print_info "Auto-generated secret: $SECRET"
    else
        SECRET=$(echo "$SECRET" | tr 'A-Z' 'a-z')
        if ! [[ $SECRET =~ ^[0-9a-f]{32}$ ]]; then
            print_error "Secret must be 32 hex characters"
            exit 1
        fi
    fi
    
    # Username
    echo ""
    read -p "Enter username [default: proxyuser]: " USERNAME
    USERNAME=${USERNAME:-proxyuser}
    
    # Ad Tag
    echo ""
    echo -e "${YELLOW}Ad Tag (for channel sponsorship):${NC}"
    read -p "Do you have an Ad Tag? (y/n): " HAS_TAG
    if [[ "$HAS_TAG" == "y" || "$HAS_TAG" == "Y" ]]; then
        read -p "Enter your 32-char Ad Tag: " AD_TAG
        if [[ ! $AD_TAG =~ ^[0-9a-f]{32}$ ]]; then
            print_error "Ad Tag must be 32 hex characters"
            exit 1
        fi
        USE_MIDDLE=true
    else
        AD_TAG=""
        USE_MIDDLE=false
        print_info "You can get an Ad Tag later from @MTProxybot"
    fi
    
    echo ""
    print_title
    echo -e "${YELLOW}Starting installation...${NC}"
    print_title
    sleep 2
    
    # Install dependencies (only essential, no Rust needed)
    print_info "Installing system dependencies..."
    apt update -qq
    apt install -y curl openssl -qq
    
    # Download binary (NO COMPILATION!)
    if [[ ! -f "$TELEMT_BIN" ]]; then
        print_info "Downloading telemt binary..."
        if ! download_binary "latest"; then
            print_error "Failed to download binary"
            exit 1
        fi
        print_info "Telemt installed successfully"
    else
        print_info "Telemt already installed"
    fi
    
    # Create user
    if ! id "telemt" &>/dev/null; then
        useradd -r -s /usr/sbin/nologin telemt
        print_info "User 'telemt' created"
    fi
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    
    # Create config file
    print_info "Creating configuration file..."
    
    cat > "$CONFIG_FILE" <<EOF
[general]
use_middle_proxy = $USE_MIDDLE
$( [ -n "$AD_TAG" ] && echo "ad_tag = \"$AD_TAG\"" )

[general.modes]
classic = false
secure = false
tls = true

[server]
port = $PORT

[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.1/32"]

[censorship]
tls_domain = "$TLS_DOMAIN"

[access.users]
$USERNAME = "$SECRET"
EOF
    
    chown -R telemt:telemt "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    chmod 640 "$CONFIG_FILE"
    print_info "Config file created: $CONFIG_FILE"
    
    # Create systemd service
    print_info "Creating systemd service..."
    
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Telemt MTProxy Service
After=network.target

[Service]
Type=simple
User=telemt
Group=telemt
ExecStart=$TELEMT_BIN $CONFIG_FILE
Restart=always
RestartSec=3
LimitNOFILE=1000000
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable telemt
    systemctl restart telemt
    
    # Open firewall port
    if command -v ufw &> /dev/null; then
        ufw allow "$PORT"/tcp 2>/dev/null && print_info "Port $PORT opened in ufw"
    fi
    
    # Get public IP
    PUBLIC_IP=$(curl -s ifconfig.me || curl -s api.ipify.org || echo "YOUR_SERVER_IP")
    
    clear
    print_title
    echo -e "${GREEN}         Installation Complete!${NC}"
    print_title
    echo ""
    print_info "Service status:"
    systemctl status telemt --no-pager --lines=0 || true
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Connection Information:${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  Server:      $PUBLIC_IP"
    echo -e "  Port:        $PORT"
    echo -e "  Secret:      $SECRET"
    echo -e "  TLS Domain:  $TLS_DOMAIN"
    echo -e "  Username:    $USERNAME"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${GREEN}Connection Link (with Fake TLS):${NC}"
    echo -e "  ${YELLOW}tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=ee$SECRET${NC}"
    echo ""
    if [[ "$USE_MIDDLE" == "true" ]]; then
        print_info "✅ Ad Tag is ACTIVE"
    else
        print_warn "⚠️  Ad Tag is NOT active. To activate:"
        echo "   1. Go to @MTProxybot on Telegram"
        echo "   2. Send /newproxy command"
        echo "   3. Send your IP: $PUBLIC_IP and port: $PORT"
        echo "   4. Send secret: $SECRET"
        echo "   5. Add received Tag to config:"
        echo "      echo 'ad_tag = \"YOUR_TAG\"' >> $CONFIG_FILE"
        echo "   6. Run: systemctl restart telemt"
    fi
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "  View status:   systemctl status telemt"
    echo "  Restart:       systemctl restart telemt"
    echo "  Stop:          systemctl stop telemt"
    echo "  View logs:     journalctl -u telemt -f"
    echo "  Show link:     ./install-telemt.sh (option 6)"
    echo ""
    read -p "Press Enter to continue..."
}

show_status() {
    clear
    systemctl status telemt --no-pager || true
    read -p "Press Enter to continue..."
}

restart_service() {
    systemctl restart telemt
    print_info "Service restarted"
    sleep 2
}

stop_service() {
    systemctl stop telemt
    print_info "Service stopped"
    sleep 2
}

uninstall_telemt() {
    echo ""
    read -p "Are you sure you want to uninstall? (y/n): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        systemctl stop telemt 2>/dev/null || true
        systemctl disable telemt 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        rm -rf "$CONFIG_DIR"
        rm -f "$TELEMT_BIN"
        systemctl daemon-reload || true
        print_info "Telemt uninstalled successfully"
    else
        print_warn "Uninstall cancelled"
    fi
    sleep 2
}

show_link() {
    clear
    if [[ -f "$CONFIG_FILE" ]]; then
        PUBLIC_IP=$(curl -s ifconfig.me || curl -s api.ipify.org || echo "YOUR_SERVER_IP")
        PORT=$(grep "^port" "$CONFIG_FILE" | awk -F'=' '{print $2}' | tr -d ' ')
        SECRET=$(grep -A1 "\[access.users\]" "$CONFIG_FILE" | tail -1 | awk -F'=' '{print $2}' | tr -d ' "')
        TLS_DOMAIN=$(grep "tls_domain" "$CONFIG_FILE" | awk -F'=' '{print $2}' | tr -d ' "')
        
        print_title
        echo -e "${GREEN}Connection Link:${NC}"
        print_title
        echo ""
        echo -e "  ${YELLOW}tg://proxy?server=$PUBLIC_IP&port=$PORT&secret=ee$SECRET${NC}"
        echo ""
        echo -e "  Server:      $PUBLIC_IP"
        echo -e "  Port:        $PORT"
        echo -e "  Secret:      $SECRET"
        echo -e "  TLS Domain:  $TLS_DOMAIN"
        echo ""
    else
        print_error "Telemt is not installed"
    fi
    read -p "Press Enter to continue..."
}

add_ad_tag() {
    clear
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_error "Telemt is not installed"
        read -p "Press Enter to continue..."
        return
    fi
    
    print_title
    echo -e "${GREEN}Add/Update Ad Tag${NC}"
    print_title
    echo ""
    read -p "Enter your 32-char Ad Tag from @MTProxybot: " AD_TAG
    if [[ ! $AD_TAG =~ ^[0-9a-f]{32}$ ]]; then
        print_error "Invalid Ad Tag. Must be 32 hex characters"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Remove old ad_tag line if exists
    sed -i '/^ad_tag =/d' "$CONFIG_FILE"
    # Add new ad_tag after [general] section
    sed -i "/^\[general\]/a ad_tag = \"$AD_TAG\"" "$CONFIG_FILE"
    # Enable middle proxy
    sed -i 's/use_middle_proxy = false/use_middle_proxy = true/' "$CONFIG_FILE"
    
    systemctl restart telemt
    print_info "Ad Tag added and service restarted"
    sleep 2
}

# Main menu loop
while true; do
    show_menu
    read -p "Select option: " opt
    
    case $opt in
        1) install_telemt ;;
        2) show_status ;;
        3) restart_service ;;
        4) stop_service ;;
        5) uninstall_telemt ;;
        6) show_link ;;
        7) add_ad_tag ;;
        0) 
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
        *) 
            print_error "Invalid option"
            sleep 1
            ;;
    esac
done
