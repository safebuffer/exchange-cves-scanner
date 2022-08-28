import requests
import re
import logging
import socket
from urllib.parse import urlparse
from .utils import *
requests.packages.urllib3.disable_warnings()
logger = logging.getLogger('Exchange-ToolKit')

class ExchangeServer(object):
    # MS-ASHTTP
    def __init__(self, host=None):
        super(ExchangeServer, self).__init__()
        self.host = host
        parse_uri = urlparse(self.host)
        if not parse_uri.scheme:
            url = '//' + self.host
            parse_uri = urlparse(url)
        domain = self.__sanitize_domain('{uri.hostname}'.format(uri=parse_uri))
        if domain:
            self.host = domain
        self.target = f"https://{self.host}/"
        self.owa_endpoint = f"{self.target}owa/"
        self.timeout = 120
        self.request_headers = {
            'User-Agent': 'Exchange ToolKit',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        }
        self.build_v, self.major, self.minor = 0,0,0
        self.servername = "Unknown"
        self.exchange_version = "Unknown"
        self.exchange_version_str = "Unknown"
        self.internal_domain = self.__get_domain_name()
        self.is_valid = self.__is_exchange()
        if self.exchange_version: 
            try:
                if not self.exchange_version == "Unknown":
                    self.build_v, self.major, self.minor = self.exchange_version.split(".")[0:3]
                    self.build_v, self.major, self.minor = int(self.build_v), int(self.major), int(self.minor)
            except Exception as e:
                logger.error(f"error getting exchange version {e}")


    def __sanitize_domain(self,domain):
        domain = domain.split('_')[0]
        domain = re.sub(r'[^\w^\.^\-]', '', domain)
        if domain.startswith('-'):
            domain = self.__sanitize_domain(domain[1:])
        elif domain.endswith('-'):
            domain = self.__sanitize_domain(domain[:-1])
        return domain

    def __is_exchange(self):
        try:
            check1,check2 = None,None
            headreq = requests.head(self.target, timeout=self.timeout ,headers=self.request_headers, verify=False)
            if '/owa/' in headreq.headers["location"]:
                self.owa_endpoint = headreq.headers["location"]
                self.servername = headreq.headers["X-FEServer"] if "X-FEServer" in headreq.headers else "Exchange-Server"
                check1 = True
            headreq = requests.head(self.target+"ews/exchange.asmx", timeout=self.timeout ,headers=self.request_headers , verify=False)
            if 'www-authenticate' in str(headreq.headers).lower():
                check2 = True
            if all([check2,check1]):
                regex = re.compile(b'href="/owa/auth/(?P<version>[]\.[0-9\.]+)/themes/resources/favicon.ico"')
                greq = requests.get(self.owa_endpoint, timeout=self.timeout,headers=self.request_headers, verify=False)
                for line in greq.iter_lines():
                    match = regex.search(line)
                    if match:
                        self.exchange_version = match.group("version").decode()
                if self.exchange_version:
                    self.exchange_version_str = get_version_string(self.exchange_version)
                return True
        except Exception as e:
            pass
            #logger.error(f"error __is_exchange {e}")
        return False

    def get_possible_hostname(self):
        is_ip = is_valid_ipv4_address(self.host)


    def __get_domain_name(self):
        return None

