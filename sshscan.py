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
# Cipher detection based on: https://stribika.github.io/2015/01/04/secure-secure-shell.html
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

def get_output(rawlist):
	if rawlist:
		rawlist = re.sub('\)', ',', rawlist)
		d = rawlist.split(',')
		ciphers = ['3des-cbc','aes128-cbc','aes192-cbc','aes256-cbc','aes128-ctr','aes192-ctr','aes256-ctr','aes128-gcm@openssh.com','aes256-gcm@openssh.com','arcfour','arcfour128','arcfour256','blowfish-cbc','cast128-cbc','chacha20-poly1305@openssh.com']
		strong_ciphers = ['chacha20-poly1305@openssh.com','aes256-gcm@openssh.com','aes128-gcm@openssh.com','aes256-ctr','aes192-ctr','aes128-ctr']
		weak_ciphers = []
		macs = ['hmac-md5','hmac-md5-96','hmac-ripemd160','hmac-sha1','hmac-sha1-96','hmac-sha2-256','hmac-sha2-512','umac-64','umac-128','hmac-md5-etm@openssh.com','hmac-md5-96-etm@openssh.com','hmac-ripemd160-etm@openssh.com','hmac-sha1-etm@openssh.com','hmac-sha1-96-etm@openssh.com','hmac-sha2-256-etm@openssh.com','hmac-sha2-512-etm@openssh.com','umac-64-etm@openssh.com','umac-128-etm@openssh.com']	
		strong_macs = ['hmac-sha2-512-etm@openssh.com','hmac-sha2-256-etm@openssh.com','hmac-ripemd160-etm@openssh.com','umac-128-etm@openssh.com','hmac-sha2-512','hmac-sha2-256','hmac-ripemd160','umac-128@openssh.com']
		weak_macs = [] 
		kex = ['curve25519-sha256','diffie-hellman-group1-sha1','diffie-hellman-group14-sha1','diffie-hellman-group-exchange-sha1','diffie-hellman-group-exchange-sha256','ecdh-sha2-nistp256','ecdh-sha2-nistp384','ecdh-sha2-nistp521']
		strong_kex = ['curve25519-sha256@libssh.org','diffie-hellman-group-exchange-sha256']
		weak_kex = []
		rlist = []
		for i in list(d):
			ci = re.sub(r'[^ -~].*', '', i)
			rlist.append(ci)
		clean_list = []
		compression = False
		for i in set(rlist):
			if i:
				clean_list.append(i)
				for i in clean_list:
					if i == "zlib@openssh.com":
						clean_list.remove(i)
						compression = True
		dmacs = []
		for i in macs:
			if i in clean_list:
				dmacs.append(i)
				if i not in strong_macs:
					weak_macs.append(i)
		dciphers = []
		for i in ciphers:
			if i in clean_list:
				dciphers.append(i)
				if i not in strong_ciphers:
					weak_ciphers.append(i)
		dkex = []
		for i in kex:
			if i in clean_list:
				dkex.append(i)
				if i not in strong_kex:
					weak_kex.append(i)

		print '    [+] Detected the following ciphers: '  			
		print_columns(dciphers)
		print '    [+] Detected the following KEX algorithms: '  			
		print_columns(dkex)
		print '    [+] Detected the following MACs: '  			
		print_columns(dmacs)
		if compression == True:
			print "    [+] Compression has been enabled!"

		if weak_ciphers:
			print '    [+] Detected the following weak ciphers: '
			print_columns(weak_ciphers)
		else:
			print '    [+] No weak ciphers detected!'	

		if weak_kex:
			print '    [+] Detected the following weak KEX algorithms: '
			print_columns(weak_kex)
		else:
			print '    [+] No weak KEX detected!'	

		if weak_macs:
			print '    [+] Detected the following weak MACs: '
			print_columns(weak_macs)
		else:
			print '    [+] No weak MACs detected!'	

def print_columns(cipherlist):
	# adjust the amount of columns to display 
	cols = 2
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
