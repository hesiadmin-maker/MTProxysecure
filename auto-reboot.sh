#!/bin/bash

echo "🔄 تنظیم ریبوت خودکار هر ۱۵ دقیقه..."

# 1. تنظیم timezone
echo "⏱️ تنظیم timezone به Asia/Tehran..."
sudo timedatectl set-timezone Asia/Tehran

# 2. پیدا کردن مسیر دقیق reboot
REBOOT_PATH=$(command -v reboot)
echo "📍 مسیر reboot پیدا شد: $REBOOT_PATH"

# 3. ساخت فایل سرویس
echo "📦 ساخت فایل every-15min-reboot.service..."
sudo tee /etc/systemd/system/every-15min-reboot.service > /dev/null <<EOF
[Unit]
Description=Reboot Every 15 Minutes

[Service]
Type=oneshot
ExecStart=$REBOOT_PATH
User=root
EOF

# 4. ساخت فایل تایمر
echo "⏰ ساخت فایل every-15min-reboot.timer..."
sudo tee /etc/systemd/system/every-15min-reboot.timer > /dev/null <<EOF
[Unit]
Description=Reboot system every 15 minutes

[Timer]
OnCalendar=*:0/15
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 5. فعال‌سازی تایمر
echo "🚀 فعال‌سازی تایمر..."
sudo systemctl daemon-reload
sudo systemctl enable --now every-15min-reboot.timer

# 6. نمایش زمان‌بندی
echo "🔍 بررسی زمان اجرای بعدی:"
systemctl list-timers --all | grep every-15min-reboot

echo "✅ تنظیمات کامل شد. سرور هر ۱۵ دقیقه ریبوت خواهد شد."
