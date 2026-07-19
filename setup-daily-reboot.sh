#!/bin/bash

echo "🛠️ تنظیم ریبوت خودکار روزانه ساعت ۶ صبح به وقت ایران..."

# 1. تنظیم timezone
echo "⏱️ تنظیم timezone به Asia/Tehran..."
sudo timedatectl set-timezone Asia/Tehran

# 2. پیدا کردن مسیر دقیق reboot
REBOOT_PATH=$(command -v reboot)
echo "📍 مسیر reboot پیدا شد: $REBOOT_PATH"

# 3. ساخت فایل سرویس
echo "📦 ساخت فایل daily-reboot.service..."
sudo tee /etc/systemd/system/daily-reboot.service > /dev/null <<EOF
[Unit]
Description=Daily Reboot

[Service]
Type=oneshot
ExecStart=$REBOOT_PATH
User=root
EOF

# 4. ساخت فایل تایمر
echo "📅 ساخت فایل daily-reboot.timer..."
sudo tee /etc/systemd/system/daily-reboot.timer > /dev/null <<EOF
[Unit]
Description=Reboot system every day at 06:00 Iran time

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 5. فعال‌سازی تایمر
echo "🚀 فعال‌سازی تایمر..."
sudo systemctl daemon-reload
sudo systemctl enable --now daily-reboot.timer

# 6. نمایش زمان‌بندی
echo "🔍 بررسی زمان اجرای بعدی:"
systemctl list-timers --all | grep daily-reboot

echo "✅ تنظیمات کامل شد. سرور هر روز ساعت ۶ صبح به وقت ایران ریبوت خواهد شد."
