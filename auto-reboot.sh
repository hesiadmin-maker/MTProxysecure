#!/bin/bash

# Create reboot script
cat << 'EOF' > /usr/local/bin/auto-reboot.sh
#!/bin/bash
/sbin/reboot
EOF

chmod +x /usr/local/bin/auto-reboot.sh

# Create systemd service
cat << 'EOF' > /etc/systemd/system/auto-reboot.service
[Unit]
Description=Auto Reboot Script

[Service]
Type=oneshot
ExecStart=/usr/local/bin/auto-reboot.sh
EOF

# Create systemd timer (1 hour)
cat << 'EOF' > /etc/systemd/system/auto-reboot.timer
[Unit]
Description=Reboot every 1 hour

[Timer]
OnBootSec=1h
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
EOF

# Reload systemd and enable timer
systemctl daemon-reload
systemctl enable --now auto-reboot.timer

echo "Auto reboot every 1 hour is now active!"
systemctl status auto-reboot.timer
