#!/usr/bin/env python
# The MIT License (MIT)
# 
# Copyright (c) 2014 Vincent Ruijter
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
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

def exchange(ip, port):
	try:
		conn = socket.create_connection((ip, port),5)
		print "[*] Connected to %s on port %i..."%(ip, port)
		version = conn.recv(50).split('\n')[0]
		conn.send('SSH-2.0-OpenSSH_6.0p1\r\n')
		print "    [+] Target SSH version is: %s" %version
		print "    [+] Retrieving ciphers..."
		ciphers = conn.recv(984)
		conn.close()
		
		return ciphers
	
	except socket.timeout:
		print "    [-] Timeout while connecting to %s on port %i\n"%(ip, port)
		return False
	
	except socket.error as e:
		if e.errno == 61:
			print "    [-] %s\n"%(e.strerror)
			pass
		else:
			print "    [-] Error while connecting to %s on port %i\n"%(ip, port)
			return False	

def validate_target(target):
	if not re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|\
				1[0-9]{2}|2[0-4][0-9]|25[0-4])($|:([1-9]{1,4}|[1-5][0-9][0-9][0-9][0-9]|\
				6[0-4][0-9][0-9][0-9]|6[0-5][0-5][0-3][0-5]))$", target):
		
		if re.match("^(([a-zA-Z0-9-.]|[a-z][a-z0-9]-.)*)([a-zA-Z0-9])($|:([1-9]{1,4}|[1-5][0-9][0-9][0-9][0-9]|\
                    6[0-4][0-9][0-9][0-9]|6[0-5][0-5][0-3][0-5]))$", target):
				
			return target
		else:
			print "[-] %s it not a valid target!"%target
			return False

	else:
		return target

def parse_target(target, level=1):
	if validate_target(target):

		if not re.search(r'[:*]', target):
			print "[*] Target %s specified without a port number, using default port 22"%target
			target = target+':22'
	
		ipport=target.split(':')

		try:
			print "[*] Initiating scan for %s on port %s" %(ipport[0], ipport[1])
			if not get_output(exchange(ipport[0], int(ipport[1]))):
				return False
	
		except IndexError:
			print "    [-] Please specify target as 'target:port'!\n"
			return False	
	
		except ValueError:
			print "    [-] Target port error, please specify a valid port!\n"
			return False	

def list_parser(list, level=1):
	try:
		fd=open(list, 'r')
		targetlist = fd.read().split('\n')
		targets = []
		for target in targetlist:
			if target:
				targets.append(target)

		print "[*] List contains %i targets to scan" %len(targets)

		error = 0
		for target in targets:
			if parse_target(target) == False:
				error+=1
		if error > 0:
			if error == len(targets):
				print "[*] Scan failed for all %i hosts!"%len(targets)
			else:
				print "[*] Scan completed for %i out of %i targets!" %((len(targets)-error), len(targets))

	except IOError as e:
		if e.filename:
			print "[-] %s: '%s'"%(e.strerror, e.filename)
		else:
			print "[-] %s"%e.strerror
		sys.exit(2)

def get_output(ciphers):
	if ciphers:
		d = ciphers.split(',')
		strong_ciphers = ['hmac-sha2-512-etm@openssh.com','hmac-sha2-256-etm@openssh.com','hmac-ripemd160-etm@openssh.com','umac-128-etm@openssh.com','hmac-sha2-512','hmac-sha2-256','hmac-ripemd160','umac-128@openssh.com','chacha20-poly1305@openssh.com','aes256-gcm@openssh.com','aes128-gcm@openssh.com','aes256-ctr','aes192-ctr','aes128-ctr','curve25519-sha256@libssh.org','diffie-hellman-group-exchange-sha256']
		rawcipher = []
		for i in list(d):
			ci = re.sub(r'[^ -~].*', '', i)
			rawcipher.append(ci)
		cipherlist = []
		compression = False
		for i in set(rawcipher):
			if i:
				cipherlist.append(i)
				for i in cipherlist:
					if i == "zlib@openssh.com":
						cipherlist.remove(i)
						compression = True
		weak_ciphers = list(set(cipherlist) - set(strong_ciphers))
		print '    [+] Detected the following ciphers: '  			
		print_columns(cipherlist)
		if compression == True:
			print "    [+] Compression has been enabled!"
		if weak_ciphers:
			print '    [+] Detected the following weak ciphers: '
			print_columns(weak_ciphers)
			return True
		else:
			print '    [+] No weak ciphers detected!'	
			return False

def print_columns(cipherlist):
	cols = 3
	while len(cipherlist) % cols != 0:
		cipherlist.append('')
	else:
		split = [cipherlist[i:i+len(cipherlist)/cols] for i in range(0, len(cipherlist), len(cipherlist)/cols)]
		for row in zip(*split):
			print "            " + "".join(str.ljust(c,37) for c in row)
	
	print "\n"

def main():
	try:
		print banner()
		parser = OptionParser(usage="usage %prog [options]", version="%prog 1.0")
		parameters = OptionGroup(parser, "Options")
	
		parameters.add_option("-t", "--target", type="string", help="Specify target as 'target' or 'target:port' (port 22 is default)", dest="target")
		parameters.add_option("-l", "--target-list", type="string", help="File with targets: 'target' or 'target:port' seperated by a newline (port 22 is default)", dest="targetlist")
		parser.add_option_group(parameters)

		options, arguments = parser.parse_args()

		target = options.target
		targetlist = options.targetlist

		if target:
			parse_target(target)		
		else:
			if targetlist:
				list_parser(targetlist)
			else:
				print "[-] No target specified!"
				sys.exit(0)

	except KeyboardInterrupt:
		print "\n[-] ^C Pressed, quitting!"
		sys.exit(3)		

if __name__ == '__main__':
	main()
