from .const import VULNERABILITIES
import socket
import requests
import json, os

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def print_red(server=None,text=""):
    tex = f"[{server.host} -> {server.servername}] {text}" if server else f"{text}"
    print(bcolors.FAIL + tex + bcolors.ENDC)


def print_info(server=None,text=""):
    tex = f"[{server.host} -> {server.servername}] {text}" if server else f"{text}"
    print(bcolors.OKBLUE + tex + bcolors.ENDC)

def print_green(server=None,text=""):
    tex = f"[{server.host} -> {server.servername}] {text}" if server else f"{text}"
    print(bcolors.OKGREEN + tex + bcolors.ENDC)


def get_version_string(version):
    ret = "Exchange Server"
    build_v, major, minor = 0,0,0
    try:
        build_v, major, minor = version.split(".")[0:3]
        build_v, major, minor = int(build_v), int(major), int(minor)
    except Exception as e:
        return ret
    if build_v == 4:
        ret = "Exchange Server 4.0"
    elif build_v == 5:
        if major == 0:
            ret = "Exchange Server 5.0"
        else:
            ret = "Exchange Server 5.5"
    elif build_v == 6:
        if major == 0:
            ret = "Exchange 2000 Server"
        else:
            ret = "Exchange Server 2003"
    elif build_v == 8:
        ret = "Exchange Server 2007"
    elif build_v == 14:
        ret = "Exchange Server 2010"
    elif build_v == 15:
        if major == 0:
            ret = "Exchange Server 2013"
        elif major == 1:
            ret = "Exchange Server 2016"
        elif major == 2:
            ret = "Exchange Server 2019"
    return ret


def version_based_scanning(exchange_server):
    if exchange_server.exchange_version == "Unknown":
        return []
    else:
        # pull remote db
        db = download_vuln_feed()
        ret = []
        for v in db:
            build_v = int(exchange_server.build_v)
            major = int(exchange_server.major)
            minor = int(exchange_server.minor)

            cond = eval(v['compare_str'])
            if cond:
                ret.append(v)
        return ret


def GetHostByAddress(ip):
    try:
        data = socket.gethostbyaddr(ip)
        host = repr(data[0])
        host = str(host)
        host = host.replace("'","")
        host = host.replace('"','')
        return host
    except Exception:
        return False



def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def get_data_ms_api(url,skip=False):
    try:
        req = requests.get(url,timeout=120,verify=True)
        if req.status_code == 200:
            json = req.json()
            if '@odata.nextLink' in json.keys():
                if skip:
                    return json
                else:
                    return json['@odata.nextLink']
            else:
                return req.json()
    except Exception as e:
        # log smt here
        return False

def download_vuln_feed():
    # https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?$orderBy=releaseDate+asc&$filter=productFamilyId+in+('100000004')+and+(releaseDate+gt+1999-01-10T00:00:00+03:00)
    #   {
    #      "id":"00000000-0000-0000-502e-000065ca9c44",
    #      "releaseDate":"2021-04-13T07:00:00Z",
    #      "releaseNumber":"2021-Apr",
    #      "product":"Microsoft Exchange Server 2016 Cumulative Update 19",
    #      "productId":11856,
    #      "productFamily":"Exchange Server",
    #      "productFamilyId":100000004,
    #      "platformId":0,
    #      "cveNumber":"CVE-2021-28482",
    #      "severityId":100000000,
    #      "severity":"Critical",
    #      "impactId":100000005,
    #      "impact":"Remote Code Execution",
    #      "issuingCna":"Microsoft",
    #      "initialReleaseDate":"2021-04-13T07:00:00Z",
    #      "baseScore":"8.8",
    #      "temporalScore":"7.7",
    #      "vectorString":"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C",
    #      "kbArticles":[
    #         {
    #            "articleName":"5001779",
    #            "articleUrl":"https://support.microsoft.com/help/5001779",
    #            "downloadName":"Security Update",
    #            "downloadUrl":"http://www.microsoft.com/download/details.aspx?familyid=52da6d67-e0c4-4af0-a133-1e47217b6309",
    #            "knownIssuesName":"5001779",
    #            "knownIssuesUrl":"https://support.microsoft.com/help/5001779",
    #            "rebootRequired":"Yes",
    #            "ordinal":1,
    #            "fixedBuildNumber":"15.01.2176.012"
    #         }
    #      ]
    #   },
    if os.path.exists('vuln_db.json'):
        sw = open('vuln_db.json','r').read()
        return json.loads(sw)
    print_info(server=None,text="[*] Downloading vuln_db.json from api.msrc.microsoft.com")
    vuln_data = []
    baseurl = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?%24orderBy=releaseDate+asc&%24filter=productFamilyId+in+%28%27100000004%27%29+and+%28releaseDate+gt+1999-01-10T00%3A00%3A00%2B03%3A00%29"
    urls = []
    urls.append(baseurl)
    try:
        while True:
            data = get_data_ms_api(urls[0])
            if type(data) == str:
                urls.insert(0, data)
            else:
                break
    except Exception as e:
        # log smt here
        return False

    for url in urls:
        data = get_data_ms_api(url,skip=True)
        if data:
            if 'value' in data.keys():
                for issue in data['value']:
                    patch_releaseDate = issue['releaseDate']
                    severity = issue.get('severity', 'Info')
                    baseScore = issue.get('baseScore', '0.0')
                    impact = issue.get('impact', 'Info')
                    cveNumber = issue.get('cveNumber', 'unknown')
                    if 'kbArticles' in issue.keys():
                        for kb in issue['kbArticles']:
                            fixed_in = kb.get('fixedBuildNumber', None)
                            if fixed_in:
                                try:
                                    build_v, major, minor = fixed_in.split(".")[0:3]
                                    build_v, major, minor = int(build_v.lstrip('0')), int(major.lstrip('0')), int(minor.lstrip('0'))
                                    version = get_version_string(fixed_in)
                                    compare_str = f"build_v == {build_v} and major == {major} and minor < {minor}"
                                    
                                    fdata = {
                                            'name':f"[{severity} - {baseScore}] {impact} {version}",
                                            'fixed_in':patch_releaseDate,
                                            'compare_str':compare_str,
                                            'fix_version':fixed_in,
                                            'CVE':cveNumber
                                        }
                                    vuln_data.append(fdata)
                                except Exception as e:
                                    pass

    with open('vuln_db.json','w',encoding='utf-8') as fs:
        json.dump(vuln_data,fs)
    return vuln_data

