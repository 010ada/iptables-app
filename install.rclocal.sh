cat > /etc/rc.local << EOF
#!/bin/sh -e
. /etc/profile ; nohup /usr/bin/python3 /root/iptables-app/main.py -a load >> /var/log/iptables-app.log 2>&1 &
exit 0
EOF
chmod +x /etc/rc.local

cat > /lib/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local Compatibility
ConditionFileIsExecutable=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
RemainAfterExit=yes
GuessMainPID=no

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable rc-local