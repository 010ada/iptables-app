import os
import re
import sys
import json
import socket
import argparse
import subprocess

import dns.rdatatype as dns_rdatatype
import dns.resolver as dns_resolver
import dns.exception as dns_exception

import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s', datefmt='%Y-%m-%d %H:%M:%S')


"""
install:
    python -m pip install dnspython
"""

# string
def is_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except Exception:
        return False


class Resolver(object):
    """docstring for Resolver"""
    def __init__(self):
        super(Resolver, self).__init__()
        self._cache = {}
        self._alternate_dns = [
            "8.8.8.8",
            "1.1.1.1",
            "223.5.5.5",
            "114.114.114.114"
        ]

    def _query(self, _dns, ns, tcp=False, rdata_type=dns_rdatatype.A):
        """
        ns >> array of dns
        tcp >> True or False
        """
        if isinstance(ns, str):
            ns = [ns]
        # logging.info(dns_resolver)
        dns_resolver.default_resolver = dns_resolver.Resolver(configure=False)
        dns_resolver.default_resolver.nameservers = ns
        dns_resolver.default_resolver.lifetime = 1.00
        """
        rdtype=<RdataType.A: 1>

        https://dnspython.readthedocs.io/en/stable/rdatatype-list.html
        """
        if hasattr(dns_resolver, "resolve"):
            return dns_resolver.resolve(_dns, rdata_type, tcp=tcp)
        return dns_resolver.query(_dns, rdata_type, tcp=tcp)

    def _query_ip(self, dns, ns_ip="8.8.8.8", tcp=False, rdata_type=dns_rdatatype.A):
        if dns in self._cache:
            return self._cache[dns]
        answers = self._query(dns, ns_ip, tcp=tcp, rdata_type=rdata_type)
        """
        get first answer
        """
        for answer in answers:
            self._cache[dns] = answer.address
            break
        return self._cache[dns]

    def _get_alternate_ns(self, ip_at_first):
        """
        这段自己也看不懂了
        """
        dns_list = self._alternate_dns.copy()
        need_delete = False
        for index in range(len(dns_list)):
            if dns_list[index] == ip_at_first:
                need_delete = True
                break
        if need_delete:
            dns_list.pop(index)
        dns_list.insert(0, ip_at_first)
        return dns_list

    def query_ip(self, dns, ns="8.8.8.8", tcp=False, rdata_type=dns_rdatatype.A):
        if is_ip(dns):
            return dns
        if not is_ip(ns):
            ns = self.query_ip(ns, ns="8.8.8.8", tcp=tcp, rdata_type=dns_rdatatype.A)
        result = None
        for _ns in self._get_alternate_ns(ns):
            try:
                for _tcp in (tcp, not tcp):
                    try:
                        result = self._query_ip(dns, ns_ip=_ns, tcp=_tcp, rdata_type=rdata_type)
                    except dns_exception.Timeout as e:
                        # logging.warning(e)
                        logging.warning("Timeout query %s @%s tcp >> %s", dns, _ns, _tcp)
                        continue
                    except dns_resolver.NoAnswer as e:
                        logging.warning("NoAnswer query %s @%s tcp >> %s", dns, _ns, _tcp)
                        raise e
                    except dns_resolver.NXDOMAIN as e:
                        logging.warning("NXDOMAIN query %s @%s tcp >> %s", dns, _ns, _tcp)
                        raise e
                    except Exception as e:
                        print(e, type(e))
                        raise e
            except dns_resolver.NoAnswer as e:
                continue
            except dns_resolver.NXDOMAIN as e:
                raise e
            except Exception as e:
                raise e
        if result is None:
            raise Exception("failed to query %s", dns)
        return result

def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", dest="server", help="create config from remote web service")
    parser.add_argument("-ns", dest="name_server", default="8.8.8.8", help="set name_server to query dns")
    parser.add_argument("-v", dest="verbose", action='count', default=0)
    return parser

def main():
    parser = get_parser()
    args = parser.parse_args()
    if args.server:
        r = Resolver()
        ret = r.query_ip(args.server, ns=args.name_server, rdata_type=dns_rdatatype.A)
        print(ret)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()