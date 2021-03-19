
import re
import os
import sys
import json
import socket
import argparse
import subprocess
from magic_repr import make_repr

from dns_resolver import Resolver

import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s', datefmt='%Y-%m-%d %H:%M:%S')


"""
install:
    python -m pip install repr
    python -m pip install dnspython
"""


r"""
    ret = re.findall(rb"Chain(.|\.)*?(?=Chain|$)", out)
    print(ret)

    为什么这个才有用
    ret = re.findall(rb"Chain[\w\W]*?(?=Chain|$)", out)

    会把 INPUT OUTPUT 一起包括进来
    ret = re.findall(rb"Chain[\w\W]*?(?:PREROUTING|POSTROUTING)[\w\W]*?(?=Chain|$)", out)
    [b'Chain PREROUTING (policy ACCEPT 14 packets, 6594 bytes)\nnum   pkts bytes target     prot opt in     out     source               destination         \n1        0     0 DNAT       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:200 to:1.1.1.1:999\n\n', b'Chain INPUT (policy ACCEPT 14 packets, 6594 bytes)\nnum   pkts bytes target     prot opt in     out     source               destination         \n\nChain OUTPUT (policy ACCEPT 215 packets, 14208 bytes)\nnum   pkts bytes target     prot opt in     out     source               destination         \n\nChain POSTROUTING (policy ACCEPT 215 packets, 14208 bytes)\nnum   pkts bytes target     prot opt in     out     source               destination         \n1        0     0 SNAT       tcp  --  *      *       0.0.0.0/0            1.1.1.1              tcp dpt:999 to:127.0.0.1'] 2


    ?: >> non capture as group
    ret = re.findall(rb"Chain[\w\W]*?(?:PREROUTING|INPUT|OUTPUT|POSTROUTING)[\w\W]*?(?=Chain|$)", out)

    [
        (
            b'parent group',
            b'PREROUTING|INPUT|OUTPUT|POSTROUTING' >> sub group
        )
    ]
    ret = re.findall(rb"(Chain[\w\W]*?(PREROUTING|INPUT|OUTPUT|POSTROUTING)[\w\W]*?)(?=Chain|$)", out)
"""

def run(cmd):
    process = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    return process.communicate()

if os.name != "nt":
    IPTABLES, iptables_err = run("which iptables")
    IPTABLES = IPTABLES.decode('utf8').split("\n")[0]
    iptables_err = iptables_err.decode('utf8')
    if iptables_err != "":
        logging.warning("err       >> %s", iptables_err)
        os.exit(1)
    logging.debug("iptables  >> %s", IPTABLES)
else:
    IPTABLES = None

# string
def is_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except Exception:
        return False

"""

"""
def validate_dict(d):
    def is_val_port(port):
        if port>65535 or port<1:
            return False
        return True
    for column in ("local_port", "server_port", "local_ip", "server"):
        if d[column] is None:
            raise Exception("{} >> {} cannot be None!".format(column, d[column]))

    for column in ("local_port", "server_port"):
        if not isinstance(d[column], int):
            d[column] = int(d[column])
        if not is_val_port(d[column]):
            raise Exception("{} >> {} is not a valid port!".format(column, d[column]))

class Rule():
    def __init__(self, rule_str = None):
        self.table = None
        self.chain = None
        self.index = None
        self.target = None          # DNAT or SNAT
        self.protocol = None
        self.des_ip = None
        self.des_port = None
        self.target_ip = None
        self.target_port = None


    __repr__ = make_repr('table', "chain", "index", "target", "protocol", "des_ip", "des_port", "target_ip", "target_port")


    """
    PREROUTING
    ['1', 'DNAT', 'tcp', '--', '0.0.0.0/0', '0.0.0.0/0', 'tcp', 'dpt:200', 'to:1.1.1.1:999']
    ['2', 'DNAT', 'tcp', '--', '0.0.0.0/0', '0.0.0.0/0', 'tcp', 'dpt:200', 'to:1.1.1.1:999']

    POSTROUTING
    ['1', 'SNAT', 'tcp', '--', '0.0.0.0/0', '1.1.1.1', 'tcp', 'dpt:999', 'to:127.0.0.1']
    ['2', 'SNAT', 'tcp', '--', '0.0.0.0/0', '1.1.1.1', 'tcp', 'dpt:999', 'to:127.0.0.1']
    """
    def loadByStr(self, rule_str, chain):
        if isinstance(rule_str, bytes):
            rule_str = rule_str.decode("utf8")
        r = rule_str.split(" ")
        # logging.info(r)
        self.table = "nat"
        self.chain = chain
        self.index = int(r[0])
        self.target = r[1]
        self.protocol = r[2]
        self.des_ip = r[5]
        self.des_port = int(r[7].split(":")[1])
        self.target_ip = r[8].split(":")[1]
        if self.target == "DNAT":
            self.target_port = int(r[8].split(":")[2])

class RuleDB():
    """
    自动加载rule

    无法确保是否存在重复的rule
    """
    def __init__(self):
        self.base_cmd = IPTABLES + " -t nat -nL --line-number"

        self.pre_cmd = IPTABLES + " -t nat -A PREROUTING -p {} -m {} --dport {} -j DNAT --to-destination {}:{}"
        self.post_cmd = IPTABLES + " -t nat -A POSTROUTING -p {} -m {} -d {} --dport {} -j SNAT --to-source {}"

        self.base_delete_cmd = "{} -t {} -D {} {}"
        self.base_executor = IPTABLES

        """
        {
            des_port => [rule, ...]
        }
        """
        self.dnat_db = {}


        """
        {
            des_port => [rule, ...]
        }
        """
        self.snat_db = {}

        self.loadDB()

    __repr__ = make_repr("base_cmd", "dnat_db", "snat_db")

    def loadDB(self):

        self.dnat_db = {}
        self.snat_db = {}

        out, err = run(self.base_cmd)
        if err != b'':
            logging.warning(err)
            sys.exit(1)

        rets = re.findall(rb"(Chain (PREROUTING|POSTROUTING)[\w\W]*?)(?=Chain|$)", out)

        def findLineSeperator(byte_string, count):
            index = 0
            _count = 0
            for by in byte_string:
                if by == 10:
                    if _count == count - 1:
                        return index
                    _count += 1
                index += 1
            # 没找到，即为空记录
            return len(byte_string)

        """
        多个空格或换行，改成一个
        开头和结尾的换行删掉
        """
        def format(s):
            s = re.sub(rb'(^\n|\n$)', b"", s)
            # \s 会匹配换行符，所以这里只能用空格
            s = re.sub(rb' {2,}', b" ", s)
            s = re.sub(rb'\n{2,}', b"\n", s)
            return s

        for parent_group in rets:
            # 第一行 chain名
            # 第二行 列名
            # 第二行以后，是规则主体
            if parent_group[1] == b"PREROUTING":
                # logging.info('load PREROUTING')
                tmp = parent_group[0]
                tmp = tmp[findLineSeperator(parent_group[0], 2) : ]
                tmp = format(tmp).decode("utf8").split("\n")
                for _tmp in tmp:
                    # logging.info(_tmp)
                    if len(_tmp) == 0 or "DNAT" not in _tmp:
                        continue
                    r = Rule()
                    r.loadByStr(_tmp, "PREROUTING")
                    self._addRule(r)
                # logging.info(tmp)
            if parent_group[1] == b"POSTROUTING":
                # logging.info('load POSTROUTING')
                tmp = parent_group[0]
                tmp = tmp[findLineSeperator(parent_group[0], 2) : ]
                tmp = format(tmp).decode("utf8").split("\n")
                for _tmp in tmp:
                    # logging.info(_tmp)
                    if len(_tmp) == 0 or "SNAT" not in _tmp:
                        continue
                    r = Rule()
                    r.loadByStr(_tmp, "POSTROUTING")
                    self._addRule(r)
                # logging.info(tmp)

    def _addRule(self, r):
        if r.chain == "PREROUTING":
            if r.des_port not in self.dnat_db:
                self.dnat_db[r.des_port] = []
            self.dnat_db[r.des_port].append(r)
        if r.chain == "POSTROUTING":
            if r.des_port not in self.snat_db:
                self.snat_db[r.des_port] = []
            self.snat_db[r.des_port].append(r)

    def _writeRules(self, rules):
        """
        结束后会再次运行命令，重新加载全部规则
        """
        for r in rules:
            if r.chain == "PREROUTING":
                out, err = run(self.pre_cmd.format(r.protocol, r.protocol, r.des_port, r.target_ip, r.target_port))
                if err != b'':
                    logging.warning(err)
                    sys.exit(1)
            elif r.chain == "POSTROUTING":
                out, err = run(self.post_cmd.format(r.protocol, r.protocol, r.des_ip, r.des_port, r.target_ip))
                if err != b'':
                    logging.warning(err)
                    sys.exit(1)
        self.loadDB()

    def addRuleByPair(self, rules, server_d):
        """
        写入一对nat规则
        """
        exist_rules = self.getRuleByLocalAddr(server_d["local_ip"], server_d["local_port"], server_d["protocol"])
        if len(exist_rules) != len(rules):
            self._deleteByRules(exist_rules)
            self._writeRules(rules)
            return

        """
        swap the array, make sure
            0 >> prerouting
            1 >> postrouting
        """
        if rules[0].chain == "POSTROUTING":
            tmp = rules[0]
            rules[0] = rules[1]
            rules[1] = tmp
        if exist_rules[0].chain == "POSTROUTING":
            tmp = exist_rules[0]
            exist_rules[0] = exist_rules[1]
            exist_rules[1] = tmp

        """
        前面根据protocol选的，故不比较protocol
        rules[1].target_ip == exist_rules[1].target_ip >> 本地网卡ip
        """
        if not (
                rules[0].des_port == exist_rules[0].des_port and \
                rules[0].target_port == exist_rules[0].target_port and \
                rules[0].target_ip == exist_rules[0].target_ip and \
                rules[1].target_ip == exist_rules[1].target_ip
            ):
            logging.info("nat rule is not same")
            # logging.info("%s %s", rules[0], exist_rules[0])
            self._deleteByRules(exist_rules)
            self._writeRules(rules)
            return
        logging.info("same nat rule, do nothing")

    def getRuleByTableChainIndex(self, table, chain, index):
        """
        return None or Rule obj
        """
        if table != "nat":
            return
        if chain == "PREROUTING":
            for _p in self.dnat_db:
                for _r in self.dnat_db[_p]:
                    if _r.index == index:
                        return _r
            return
        if chain == "POSTROUTING":
            for _p in self.snat_db:
                for _r in self.snat_db[_p]:
                    if _r.index == index:
                        return _r
            return
        return

    def getRuleByTargetAndIndex(self, target, index):
        """
        return None or Rule obj
        """
        if target == "DNAT":
            return self.getRuleByTableChainIndex("nat", "PREROUTING", index)
        if target == "SNAT":
            return self.getRuleByTableChainIndex("nat", "POSTROUTING", index)
        return

    # local 0.0.0.0/0 will be matched, too
    def getRuleByLocalAddr(self, local_ip, local_port, protocol):
        ret = []
        # 不同的dnat可能有不同的转发目标
        ret_des_addr = []
        if local_port in self.dnat_db:
            for r in self.dnat_db[local_port]:
                if (r.des_ip == "0.0.0.0/0" or r.des_ip == local_ip) and r.protocol == protocol:
                    ret.append(r)
                    ret_des_addr.append({
                        "target_ip" : r.target_ip,
                        "target_port" : r.target_port
                    })
        for des_addr in ret_des_addr:
            if des_addr["target_port"] in self.snat_db:
                for r in self.snat_db[des_addr["target_port"]]:
                    if r.des_ip == des_addr["target_ip"] and r.protocol == protocol:
                        ret.append(r)
        return ret

    # delete a prerouting rule, must delete a postrouting rule

    def deleteByTableChainAndIndex(self, table, chain, index):
        if table != "nat":
            raise Exception("need finish delete at table >> {}".format(table))
        if not (chain == "PREROUTING" or chain == "POSTROUTING"):
            raise Exception("need finish delete at chain >> {}".format(chain))
        logging.info("delete index >> %d", index)
        out, err = run(self.base_delete_cmd.format(self.base_executor, table, chain, index))
        if err != b'':
            print(err)
            sys.exit(1)
        # print(out)
        return

    def _deleteByRules(self, rules):
        """
        结束后会再次运行命令，重新加载全部规则
        """
        deleted_index_s = {
            "PREROUTING" : [],
            "POSTROUTING" : []
        }

        def cal_index(index, deleted_index_s):
            origin_index = index
            for deleted_index in deleted_index_s:
                if deleted_index > origin_index:
                    continue
                index -= 1
            if index < 1:
                return 1
            return index

        for r in rules:
            # logging.info("delete")
            if r.table != "nat" or not (r.chain == "PREROUTING" or r.chain == "POSTROUTING"):
                continue
            # logging.info(r)
            logging.info("origin index >> %d", r.index)
            self.deleteByTableChainAndIndex(r.table, r.chain, cal_index(r.index, deleted_index_s[r.chain]))
            deleted_index_s[r.chain].append(r.index)
    
        self.loadDB()

    def deleteByLocalAddr(self, local_ip, local_port, protocol):
        rs = self.getRuleByLocalAddr(local_ip, local_port, protocol)
        # logging.info(rs)
        self._deleteByRules(rs)

# 可以确保只有一个local addr的映射
class ConfigDB():
    """
    自动加载, default is config.json
    """
    def __init__(self, cfgFile=None):
        self.config = []
        if cfgFile == None:
            d = os.path.dirname(__file__)
            if d != "":
                self.cfgFile = d + "/" + "config.json"
            else:
                self.cfgFile = "config.json"
        else:
            self.cfgFile = cfgFile
        self.load()

        self._resolver = Resolver()

    __repr__ = make_repr("cfgFile", "config")

    def load(self, cfgFile=None):
        if cfgFile != None:
            self.cfgFile = cfgFile
        if os.path.exists(self.cfgFile):
            if os.stat(self.cfgFile).st_size > 1:
                with open(self.cfgFile, "r") as f:
                    self.config = json.loads(f.read())
        else:
            logging.info("create {}!".format(self.cfgFile))

    def writeToDisk(self):
        # print('config', self.config)
        with open(self.cfgFile, "w") as f:
            f.write(json.dumps(self.config, indent=True))

    def getByName(self, name):
        pass

    def getByIP(self, ip):
        pass

    def getByDNS(self, dns):
        pass

    # local addr
    # return index
    def getByLocalAddr(self, local_ip=None, local_port=None, protocol=None):
        if local_port is None or local_port is None or protocol is None:
            raise Exception("param not enough!")
        for i in range(len(self.config)):
            cfg = self.config[i]
            if cfg["local_ip"] == local_ip and cfg["local_port"] == local_port and cfg["protocol"] == protocol:
                return i
        return

    def isExistByLocalAddr(self, local_ip=None, local_port=None, protocol=None):
        index = self.getByLocalAddr(local_ip=local_ip, local_port=local_port, protocol=protocol)
        if index is not None:
            return True
        return False

    def delByLocalAddr(self, local_ip=None, local_port=None, protocol=None):
        index = self.getByLocalAddr(local_ip=local_ip, local_port=local_port, protocol=protocol)
        if index is not None:
            del self.config[index]
        return True

    def resolveIP(self, server_d):
        ns_ip = None
        if is_ip(server_d["server"]):
            return server_d["server"]
        if is_ip(server_d["name_server"]):
            ns_ip = server_d["name_server"]
        else:
            ns_ip = self._resolver.query_ip(server_d["name_server"])
        return self._resolver.query_ip(server_d["server"], ns=ns_ip)

    """
    添加server_ip字段
    判断server是否为dns，是则获取ip
    """
    def genServerByDict(self, server_d):
        validate_dict(server_d)
        server_d["server_ip"] = None
        server_d["server_ip"] = self.resolveIP(server_d)
        return server_d

    def addServer(self, server_d):
        server_d = self.genServerByDict(server_d)
        exist_index = self.getByLocalAddr(server_d["local_ip"], server_d["local_port"], server_d["protocol"])
        if exist_index is not None:
            logging.info("replace %s", server_d)
            self.config[exist_index] = server_d
        else:
            self.config.append(server_d)

    """
    return changed config >> [config...]
    may return zero list  >> []
    """
    def syncIP(self):
        ret = []
        for cfg in self.config:
            if not is_ip(cfg["server"]):
                new_ip = self.resolveIP(cfg)
                if new_ip != cfg["server_ip"]:
                    cfg["server_ip"] = new_ip
                    ret.append(cfg)
        if len(ret) > 0:
            logging.info("some ip changed")
            self.writeToDisk()
        else:
            logging.info("ip didn't changed")
        return ret

class Manager():
    def __init__(self):
        self.config_db = ConfigDB()
        self.rule_db = RuleDB()

        """
        local interface ip

        lo
        docker**
        
        others

        """

    def dictToRules(self, server_d):
        result = []
        # dnat
        r = Rule()
        r.table = "nat"
        r.chain = "PREROUTING"
        r.target = "DNAT"
        r.des_ip = server_d["local_ip"]
        r.des_port = server_d["local_port"]
        r.target_ip = server_d["server_ip"]
        r.target_port = server_d["server_port"]
        r.protocol = server_d["protocol"]
        result.append(r)
        # snat
        r = Rule()
        r.table = "nat"
        r.chain = "POSTROUTING"
        r.target = "SNAT"
        r.des_ip = server_d["server_ip"]
        r.des_port = server_d["server_port"]
        r.target_ip = server_d["local_ip"]
        r.protocol = server_d["protocol"]
        result.append(r)
        return result

    def addServerByDict(self, server_d):
        """
        nat rule
        先写入config文件，再写入nftable
        """
        # logging.info("%s %s", self.config_db, self.rule_db)
        self.config_db.addServer(server_d)
        self.config_db.writeToDisk()
        self.rule_db.addRuleByPair(self.dictToRules(server_d), server_d=server_d)

    def syncIP(self):
        logging.info("processing sync ip")
        changed_cfg_list = self.config_db.syncIP()
        for cfg in changed_cfg_list:
            self.rule_db.addRuleByPair(self.dictToRules(cfg), server_d=cfg)

    def writeRules(self):
        """
        write rules from config to iptables
        """
        for cfg in self.config_db.config:
            self.rule_db.addRuleByPair(self.dictToRules(cfg), server_d=cfg)


def getArg():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, epilog="Example: -p 1080 -s {a.b.c.com|ip} -sp 65500 -ns 8.8.8.8 -proto {tcp|udp|udp,tcp}")
    parser.add_argument("-a", "--action", dest="action", help="[load] load rules to iptables\n[sync] sync ip for dns")

    parser.add_argument("-nic", dest="nic", help="get local ip by nerwork card")

    parser.add_argument("-l", "--local-ip", dest="local_ip", default="0.0.0.0", help="local ip")
    parser.add_argument("-p", "--local-port", type=int, dest="local_port", help="local port")
    
    parser.add_argument("-proto", dest="protocol", default="tcp", help="protocol {tcp|udp|tcp,udp}")

    parser.add_argument("-s", "--server-ip", "--server-dns", dest="server", help="dns/ip as server address")
    parser.add_argument("-sp", "--server-port", type=int, dest="server_port", help="server port")
    parser.add_argument("-ns", "--name-server", dest="name_server", default="8.8.8.8", help="name server for dns")
    parser.add_argument("-q", "--quiet", dest="q", help="print error only, no more bothering msg")
    arg = parser.parse_args()
    return arg

"""
{add|del|edit} from commandline
    write to config file
    sync to iptables
"""
def main():
    arg = getArg()
    m = Manager()
    if arg.action != None:
        if arg.action == "load":
            m.writeRules()
        elif arg.action == "sync":
            m.syncIP()
    else:
        if arg.protocol == "tcp,udp" or arg.protocol == "udp,tcp":
            for proto in ("tcp", "udp"):
                d = {
                    "local_ip" : arg.local_ip,
                    "local_port" : arg.local_port,
                    "server" : arg.server,
                    "server_port" : arg.server_port,
                    "name_server" : arg.name_server,
                    "protocol" : proto
                }
                m.addServerByDict(d)
        elif arg.protocol == "tcp" or arg.protocol == "udp":
            d = {
                "local_ip" : arg.local_ip,
                "local_port" : arg.local_port,
                "server" : arg.server,
                "server_port" : arg.server_port,
                "name_server" : arg.name_server,
                "protocol" : arg.protocol
            }
            m.addServerByDict(d)
        else:
            raise Exception("invalid protocol >> {}".format(arg.protocol))


"""
*/1 * * * * python main.py -a sync
"""

if __name__ == "__main__":
    main()
