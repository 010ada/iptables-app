# iptables-app

## deploy
```
git clone https://github.com/010ada/iptables-app

cd iptables-app
bash install.sh

# 查看网卡ip
ip addr

# 查看${name server}
dig NS ${dns}

python3 main.py -l ${网卡ip} -p ${转发端口} -s ${server.ddns} -sp ${server.port} -ns ${name server} -proto tcp

```
