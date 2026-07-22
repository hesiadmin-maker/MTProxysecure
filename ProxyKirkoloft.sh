#!/bin/bash

set -e

echo "🔧 نصب پیش‌نیازها..."
apt update
apt install -y git curl build-essential libssl-dev zlib1g-dev

echo "📥 کلون و کامپایل MTProxy..."
git clone https://github.com/GetPageSpeed/MTProxy
cd MTProxy
make
cd objs/bin

echo "📄 دریافت فایل‌های کانفیگ از تلگرام..."
curl -s https://core.telegram.org/getProxySecret -o proxy-secret
curl -s https://core.telegram.org/getProxyConfig -o proxy-multi.conf

echo "🔐 ساخت یوزر محدود mtproxy..."
useradd -r -s /usr/sbin/nologin mtproxy || true

echo "📁 انتقال فایل‌ها به /opt/mtproxy..."
mkdir -p /opt/mtproxy
cp mtproto-proxy proxy-secret proxy-multi.conf /opt/mtproxy/
chown -R mtproxy:mtproxy /opt/mtproxy
chmod 750 /opt/mtproxy

echo "📈 تنظیم nofile برای یوزر mtproxy..."
grep -q "mtproxy" /etc/security/limits.conf || cat >> /etc/security/limits.conf <<EOF
mtproxy soft nofile 100000
mtproxy hard nofile 100000
EOF

echo "⚙️ تنظیم global برای systemd..."
sed -i '/^#DefaultLimitNOFILE=/c\DefaultLimitNOFILE=100000' /etc/systemd/system.conf
sed -i '/^#DefaultLimitNOFILE=/c\DefaultLimitNOFILE=100000' /etc/systemd/user.conf

echo "🛡️ ساخت فایل سرویس systemd..."
cat > /etc/systemd/system/mtproxy.service <<EOF
[Unit]
Description=MTProto Proxy Service (Hardened)
After=network.target

[Service]
Type=simple
User=mtproxy
WorkingDirectory=/opt/mtproxy
ExecStart=/opt/mtproxy/mtproto-proxy \\
  -p 8888 \\
  -H 443 \\
  -S 1603010200010001fc030386e24c3add \\
  --http-stats \\
  --aes-pwd proxy-secret proxy-multi.conf \\
  -P 6d27cee200722a40c3945ede471df4a1 \\
  -D biscotti.yektanet.com \\
  -M 0
Restart=always
RestartSec=3
LimitNOFILE=100000

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=yes
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallFilter=@system-service
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadOnlyPaths=/opt/mtproxy
ReadWritePaths=/opt/mtproxy/proxy-secret /opt/mtproxy/proxy-multi.conf

[Install]
WantedBy=multi-user.target
EOF

echo "🔄 ری‌لود systemd و ری‌استارت سیستم..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable mtproxy

echo "✅ نصب کامل شد. لطفاً سیستم را ری‌استارت کن تا تنظیمات nofile اعمال شوند:"
echo "sudo reboot"
