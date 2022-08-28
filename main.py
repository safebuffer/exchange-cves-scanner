__author__ = "Hossam Mohamed"
__email__ = "wazehell@outlook.com"
import logging
import argparse
import sys
from multiprocessing.dummy import Pool
import os

from exlife import *

logger = logging.getLogger('Exchange-ToolKit')
MAX_POOL = 10

GLOBAL_OPTIONS = None

def get_valid_domain(exchange_server):
    pass

def cve_scan(exchange_server):
    results = version_based_scanning(exchange_server)
    if len(results):
        for r in results:
            msg = "\n"
            msg += r['name'] + "\n"
            msg += f"Fixed In {r['fix_version']} Current Version {exchange_server.exchange_version} \n"
            msg += f"CVE : {r['CVE']} Patch Date {r['fixed_in']} \n"
            msg += "\n"
            print_red(server=exchange_server, text=msg)
        if GLOBAL_OPTIONS.outputfile:
            with open(GLOBAL_OPTIONS.outputfile,'w',encoding='utf-8') as fs:
                json.dump(results,fs)
    else:
        print_green(server=exchange_server,text=f"No CVE Found for {exchange_server.exchange_version} {exchange_server.exchange_version_str}")

def server_main(server=None):
    global GLOBAL_OPTIONS
    server = server.replace('http://','')
    server = server.replace('https://','')
    server = server.replace('/','')
    server_object = ExchangeServer(host=server)
    if server_object.is_valid:
        print_info(server=server_object, text=f"{server_object.exchange_version} {server_object.exchange_version_str}")
        cve_scan(server_object)
    else:
        pass
        #print_red(text=f"{server} Not Valid Exchange Server")

def main(options):
    global MAX_POOL,GLOBAL_OPTIONS
    GLOBAL_OPTIONS = options
    targets = options.targets
    single_target = options.target
    MAX_POOL = options.threads
    if not single_target and not targets:
        print_red(text="Exchange-ToolKit needs a target")
        exit()
    if single_target:
        server_main(single_target)
    else:
        hosts = []
        if os.path.isfile(targets):
            for t in open(targets,'r').readlines():
                t = t.replace('\n','')
                hosts.append(t) if t not in hosts else None
            tpool = Pool(MAX_POOL)
            fmap = tpool.map(server_main, hosts)
        else:
            print_red(text="Exchange-ToolKit cannot open targets file")



if __name__ == '__main__':
    
	parser = argparse.ArgumentParser(usage=f"{sys.argv[0]} -targets ips.txt", add_help = True, description = "Exchange ToolKit")

	parser.add_argument('-target', action='store', help='target IP/Domain eg : mail.company.com')
	parser.add_argument('-targets', action='store', help='Targets List')

	group = parser.add_argument_group('ToolKit Options')
	group.add_argument('-debug', action='store_true', help='Turn DEBUG output ON',default=False)
	group.add_argument('-threads', action='store', metavar = "int" , help='Number of threads',default=10, type=int)

	outputs = parser.add_argument_group('Output')
	outputs.add_argument('-outputfile', action="store", help='Output File Path', required=False, type=str)

	options = parser.parse_args()

	if options.debug:
		logger.setLevel(logging.DEBUG)
	else:
		logger.setLevel(logging.INFO)


	if len(sys.argv) > 1:
		try:
			main(options)
		except KeyboardInterrupt:
			print_red(text="Closing Exchange-ToolKit")
			exit()
	else:
		parser.print_help()
		sys.exit(1)




