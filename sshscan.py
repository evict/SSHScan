#!/usr/bin/env python
import sys
import socket
from optparse import OptionParser, OptionGroup

def banner():
	banner = """
		 _____ _____ _   _ _____                 
		/  ___/  ___| | | /  ___|                
		\ `--.\ `--.| |_| \ `--.  ___ __ _ _ __  
		 `--. \`--. |  _  |`--. \/ __/ _` | '_ \ 
		/\__/ /\__/ | | | /\__/ | (_| (_| | | | |
		\____/\____/\_| |_\____/ \___\__,_|_| |_|
	     						evict
			"""                               
	return banner

def connection():
	conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	return conn 

def exchange(conn, ip, port, verbose):
	try:
		conn.connect((ip, port))
		print "[*] Connected to %s on port %i" %(ip, port)
		version = conn.recv(50)
		conn.send('SSH-2.0-OpenSSH_6.0p1\r\n')
		
		print "[+] Retrieving ciphers..."
		ciphers = conn.recv(984)
		conn.close()
		
		if verbose == True:
			print "[++] Target SSH version: %s" %version
			print "[++] Cipher output: %s" %ciphers
	
		return ciphers

	except socket.error:
		print "Error connecting to %s on port %i"%(ip, port)
		sys.exit(1)
		
def list_parser(list):
	try:
		fd=open(list, 'r')
		targetlist = fd.read().split('\n')
		targets = []
		for target in targetlist:
			if target:
				targets.append(target)

		return targets
	
	except IOError:
		print "Error with input file:\n\t\t\tPlease specify targets on a seperate line as target:port"
		sys.exit(2)

def get_output(ciphers):
	d = ciphers.split(',')
	weak_ciphers = ['aes128-cbc','3des-cbc','blowfish-cbc','cast128-cbc','aes192-cbc','aes256-cbc','rijndael-cbc@lysator.liu.se','aes128-cbc','3des-cbc','blowfish-cbc','cast128-cbc','aes192-cbc','aes256-cbc','rijndael-cbc@lysator.liu.se','hmac-md5','hmac-sha2-256-96','hmac-sha2-512-96','hmac-sha1-96','hmac-md5-96,hmac-md5','hmac-sha2-256-96','hmac-sha2-512-96','hmac-sha1-96','hmac-md5-96']
	n = []
	for i in d:
		for j in weak_ciphers:
			if i == j:
				n.append(i)
	print '[+] Detected the following weak ciphers:\n--[!] ' + '\n--[!] ' ''.join([str(item) for item in set(n)])

def main():
	print banner()
	parser = OptionParser(usage="usage %prog [options]", version="%prog 1.0")
	parameters = OptionGroup(parser, "Options")

	parameters.add_option("-t", "--target", type="string", help="target:port", dest="target")
	parameters.add_option("-l", "--target-list", type="string", help="list with targets seperated by a newline: target:port", dest="targetlist")
	parameters.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False)
	parser.add_option_group(parameters)

	options, arguments = parser.parse_args()

	target = options.target
	targetlist = options.targetlist
	verbose = options.verbose

	if target:
		ipport = target.split(':')
		get_output(exchange(connnection(), ipport[0], int(ipport[1]), verbose))
	else:
		if targetlist is not None:
			targets = list_parser(targetlist)
			for target in targets:
				ipport = target.split(':')
				get_output(exchange(connection(), ipport[0], int(ipport[1]), verbose))
		else:
			print "No target specified!"

if __name__ == '__main__':
	main()
