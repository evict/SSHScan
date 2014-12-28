#!/usr/bin/env python
#The MIT License (MIT)
#
#Copyright (c) 2014 Vincent Ruijter
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
#

import sys, re
import socket
from optparse import OptionParser, OptionGroup

def banner():
	banner = """
		 _____ _____ _    _ _____                      
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

def exchange(conn, ip, port):
	try:
		conn.connect((ip, port))
		print "[*] Connected to %s on port %i..."%(ip, port)
		version = conn.recv(50)
		conn.send('SSH-2.0-OpenSSH_6.0p1\r\n')
		
		print "    [+] Retrieving ciphers..."
		ciphers = conn.recv(984)
		conn.close()
		
		if verbose == True:
			print "    [++] Target SSH version: %s" %version
			print "    [++] Cipher output: %s" %ciphers
	
		return ciphers

	except socket.error:
		print "    [-] Error connecting to %s on port %i!\n"%(ip, port)
		pass

def parse_target(target, count):
	if not re.search(r'[:]', target):
		print "[*] Target %s specified without a port number, using default port 22"%target
		target = target+':22'
	
	ipport=target.split(':')
	error=0	

	try:
		print "[*] Initiating scan for %s on port %s" %(ipport[0], ipport[1])
		get_output(exchange(connection(), ipport[0], int(ipport[1])))
	
	except IndexError:
		print "    [-] Please specify target as 'target:port'!\n"
		error+=1
		pass
	
	except ValueError:
		print "    [-] Target port error, please specify a valid port!\n"
		error+=1
		pass
	
	print "[*] Scan successful for %i out of %i targets!" %((count-error), count)

def list_parser(list):
	try:
		fd=open(list, 'r')
		targetlist = fd.read().split('\n')
		targets = []
		for target in targetlist:
			if target:
				targets.append(target)

		print "[*] List contains %i targets to scan" %len(targets)

		for target in targets:
			parse_target(target, len(targets))

	except IOError:
		print "    [-] Error with input file:\n            Please specify targets on a seperate line as target or target:port!\n"
		sys.exit(2)

def get_output(ciphers):
	if ciphers:
		d = ciphers.split(',')
		weak_ciphers = ['aes128-cbc','3des-cbc','blowfish-cbc','cast128-cbc','aes192-cbc','aes256-cbc','rijndael-cbc@lysator.liu.se','aes128-cbc','3des-cbc','blowfish-cbc','cast128-cbc','aes192-cbc','aes256-cbc','rijndael-cbc@lysator.liu.se','hmac-md5','hmac-sha2-256-96','hmac-sha2-512-96','hmac-sha1-96','hmac-md5-96,hmac-md5','hmac-sha2-256-96','hmac-sha2-512-96','hmac-sha1-96','hmac-md5-96']
		n = []
		for i in list(d):
			ci = re.sub(r'[^ -~].*', '', i)
			for j in weak_ciphers:
				if ci == j:
					n.append(ci)
		print '    [+] Detected the following weak ciphers:\n        [!] ' + '\n        [!] ' ''.join([str(item) for item in set(n)]) + '\n'
		return True
	else:
		return False

def main():
	print banner()
	parser = OptionParser(usage="usage %prog [options]", version="%prog 1.0")
	parameters = OptionGroup(parser, "Options")

	parameters.add_option("-t", "--target", type="string", help="Specify target as 'target' or 'target:port' (port 22 is default)", dest="target")
	parameters.add_option("-l", "--target-list", type="string", help="File with targets: 'target' or 'target:port' seperated by a newline (port 22 is default)", dest="targetlist")
	parameters.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False)
	parser.add_option_group(parameters)

	options, arguments = parser.parse_args()

	target = options.target
	targetlist = options.targetlist
	global verbose 
	verbose = options.verbose

	if target:
		print parse_target(target)		
	else:
		if targetlist:
			list_parser(targetlist)
		else:
			print "    [-] No target specified!"
			sys.exit(0)

if __name__ == '__main__':
	main()
