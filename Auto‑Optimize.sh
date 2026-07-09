#!/bin/bash

echo "🔧 Applying MTProto sysctl optimizations..."

# Increase backlog queues
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Enable SYN cookies (protection)
sysctl -w net.ipv4.tcp_syncookies=1

# Reduce FIN timeout (faster cleanup)
sysctl -w net.ipv4.tcp_fin_timeout=10

# Reuse TIME_WAIT sockets
sysctl -w net.ipv4.tcp_tw_reuse=1

# Make settings permanent
cat <<EOF >> /etc/sysctl.conf

# MTProto Optimizations
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_tw_reuse=1
EOF

sysctl -p

echo "✅ Sysctl applied."

echo "📊 Checking connection status..."

echo "TIME_WAIT:"
ss -tuna | grep TIME_WAIT | wc -l

echo "SYN:"
ss -tuna | grep SYN | wc -l

echo "TOTAL CONNECTIONS:"
ss -tuna | wc -l

echo "🎉 MTProto optimization completed."
