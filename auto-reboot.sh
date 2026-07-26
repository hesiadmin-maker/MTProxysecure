#!/bin/bash

echo "🔄 تنظیم ریبوت خودکار هر ساعت..."

# 1. تنظیم timezone
echo "⏱️ تنظیم timezone به Asia/Tehran..."
sudo timedatectl set-timezone Asia/Tehran

# 2. پیدا کردن مسیر دقیق reboot
REBOOT_PATH=$(command -v reboot)
echo "📍 مسیر reboot پیدا شد: $REBOOT_PATH"

# 3. ساخت فایل سرویس
echo "📦 ساخت فایل hourly-reboot.service..."
sudo tee /etc/systemd/system/hourly-reboot.service > /dev/null <<EOF
[Unit]
Description=Hourly Reboot

[Service]
Type=oneshot
ExecStart=$REBOOT_PATH
User=root
EOF

# 4. ساخت فایل تایمر
echo "⏰ ساخت فایل hourly-reboot.timer..."
sudo tee /etc/systemd/system/hourly-reboot.timer > /dev/null <<EOF
[Unit]
Description=Reboot system every hour

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 5. فعال‌سازی تایمر
echo "🚀 فعال‌سازی تایمر..."
sudo systemctl daemon-reload
sudo systemctl enable --now hourly-reboot.timer

# 6. نمایش زمان‌بندی
echo "🔍 بررسی زمان اجرای بعدی:"
systemctl list-timers --all | grep hourly-reboot

echo "✅ تنظیمات کامل شد. سرور هر ساعت ریبوت خواهد شد."
