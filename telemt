#!/bin/bash
set -e

SERVICE_FILE="/etc/systemd/system/telemt.service"
CONFIG_DIR="/etc/telemet"
CONFIG_FILE="$CONFIG_DIR/telemet.toml"
TELEMT_BIN="/usr/local/bin/telemt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[✓]${NC} $1"; }
echo_error() { echo -e "${RED}[✗]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

clear
echo "=========================================="
echo "     Telemt MTProxy Auto Installer"
echo "        با پشتیبانی از Ad Tag"
echo "=========================================="
echo ""

# دریافت اطلاعات از کاربر
read -p "پورت (پیش‌فرض 443): " PORT
PORT=${PORT:-443}

read -p "دامنه Fake TLS (مثال: www.google.com): " TLS_DOMAIN
while [[ -z "$TLS_DOMAIN" ]]; do
    echo_error "دامنه الزامی است"
    read -p "دامنه Fake TLS: " TLS_DOMAIN
done

read -p "سکرت (Enter بزنید تا اتوماتیک ساخته شود): " SECRET
if [[ -z "$SECRET" ]]; then
    SECRET=$(openssl rand -hex 16)
    echo_info "سکرت ساخته شد: $SECRET"
else
    SECRET=$(echo "$SECRET" | tr 'A-Z' 'a-z')
    if ! [[ $SECRET =~ ^[0-9a-f]{32}$ ]]; then
        echo_error "سکرت باید 32 کاراکتر هگز باشد"
        exit 1
    fi
fi

read -p "نام کاربری (پیش‌فرض: proxyuser): " USERNAME
USERNAME=${USERNAME:-proxyuser}

echo ""
echo_warn "برای Ad Tag (اسپانسری):"
read -p "آیا Tag دارید؟ (y/n): " HAS_TAG
if [[ "$HAS_TAG" == "y" || "$HAS_TAG" == "Y" ]]; then
    read -p "Tag 32 کاراکتری خود را وارد کنید: " AD_TAG
    if [[ ! $AD_TAG =~ ^[0-9a-f]{32}$ ]]; then
        echo_error "Tag باید 32 کاراکتر هگز باشد"
        exit 1
    fi
    USE_MIDDLE=true
else
    AD_TAG=""
    USE_MIDDLE=false
    echo_info "می‌توانید بعداً با مراجعه به @MTProxybot Tag دریافت کنید"
fi

read -p "تعداد Worker (پیش‌فرض: تعداد هسته‌ها): " WORKERS
if [[ -z "$WORKERS" ]]; then
    WORKERS=$(nproc)
fi

echo ""
echo "=========================================="
echo "شروع نصب..."
echo "=========================================="
sleep 2

# نصب وابستگی‌ها
echo_info "نصب وابستگی‌های سیستم..."
apt update -qq
apt install -y git curl build-essential pkg-config libssl-dev openssl -qq

# نصب Rust اگر وجود نداشت
if ! command -v cargo &> /dev/null; then
    echo_info "نصب Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# کامپایل telemt
if [[ ! -f "$TELEMT_BIN" ]]; then
    echo_info "دانلود و کامپایل telemt (حدود ۲-۵ دقیقه)..."
    cd /tmp
    rm -rf telemt
    git clone --quiet https://github.com/telemt/telemt
    cd telemt
    cargo build --release -q
    cp ./target/release/telemt "$TELEMT_BIN"
    cd /
    rm -rf /tmp/telemt
    echo_info "telemt نصب شد"
else
    echo_info "telemt از قبل نصب شده است"
fi

# ایجاد کاربر
if ! id "telemt" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin telemt
    echo_info "کاربر telemt ساخته شد"
fi

# ایجاد پوشه کانفیگ
mkdir -p "$CONFIG_DIR"

# ساخت فایل کانفیگ
echo_info "ساخت فایل کانفیگ..."

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
echo_info "فایل کانفیگ ساخته شد: $CONFIG_FILE"

# ساخت سرویس systemd
echo_info "ساخت سرویس systemd..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Telemt MTProxy Service
After=network.target

[Service]
Type=simple
User=telemt
Group=telemt
ExecStart=$TELEMT_BIN -c $CONFIG_FILE
Restart=always
RestartSec=3
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable telemt
systemctl restart telemt

# باز کردن پورت در فایروال
if command -v ufw &> /dev/null; then
    ufw allow "$PORT"/tcp 2>/dev/null && echo_info "پورت $PORT در ufw باز شد"
fi

echo ""
echo "=========================================="
echo "        نصب با موفقیت انجام شد!"
echo "=========================================="
echo ""
echo_info "وضعیت سرویس:"
systemctl status telemt --no-pager --lines=0
echo ""
echo "📋 اطلاعات اتصال:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  آدرس:      $(curl -s ifconfig.me)"
echo -e "  پورت:      $PORT"
echo -e "  سکرت:      $SECRET"
echo -e "  دامنه TLS: $TLS_DOMAIN"
echo -e "  کاربر:     $USERNAME"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔗 لینک اتصال (با Fake TLS):"
echo -e "  ${GREEN}tg://proxy?server=$(curl -s ifconfig.me)&port=$PORT&secret=ee$SECRET${NC}"
echo ""
if [[ "$USE_MIDDLE" == "true" ]]; then
    echo_info "✅ Ad Tag فعال است"
else
    echo_warn "⚠️  Ad Tag فعال نیست. برای فعال کردن:"
    echo "   1. به @MTProxybot در تلگرام بروید"
    echo "   2. دستور /newproxy بزنید"
    echo "   3. IP و پورت $PORT را بفرستید"
    echo "   4. سکرت $SECRET را بفرستید"
    echo "   5. Tag دریافتی را در فایل کانفیگ اضافه کنید:"
    echo "      echo 'ad_tag = \"TAG\"' >> $CONFIG_FILE"
    echo "   6. systemctl restart telemt"
fi
echo ""
echo "📝 دستورات مفید:"
echo "  مشاهده وضعیت: systemctl status telemt"
echo "  ریستارت:      systemctl restart telemt"
echo "  توقف:         systemctl stop telemt"
echo "  مشاهده لاگ:   journalctl -u telemt -f"
echo ""
echo "=========================================="
