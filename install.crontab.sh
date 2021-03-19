crontab -l | grep -v ^# | grep -q iptables-app
[[ $? -eq 0 ]] && exit 0

TMP_FILE="/tmp/$(date +'%s').crontab.tmp"
crontab -l > $TMP_FILE

echo "*/1 * * * * . /etc/profile ; /usr/bin/python3 /root/iptables-app/main.py -a sync >> /var/log/iptables-app.log 2>&1" >> $TMP_FILE

crontab $TMP_FILE
