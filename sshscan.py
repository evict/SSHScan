#!/usr/bin/env python
# The MIT License (MIT)
#
# Copyright (c) 2016 Vincent Ruijter
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
      `--. \`--. |  _  |`--. \/ __/ _` | '_ \\
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
	list = target.split(":")
	if len(list) != 1 and len(list) != 2: # only valid states
		print "[-] %s is not a valid target!"%target
		return False
	hostname = list[0]
	if len(hostname) > 255:
		print "[-] %s is not a valid target!"%target
		return False
	if hostname[-1] == ".":
		hostname = hostname[:-1] # strip exactly one dot from the right, if present
	allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
	if not all(allowed.match(x) for x in hostname.split(".")):
		print "[-] %s is not a valid target!"%target
		return False
	if len(list) == 2: # there is a specific port indication
		port = list[1]
		try:
			validport = int(port)
			if validport < 1 or validport > 65535:
				print "[-] %s is not a valid target!"%target
				return False
		except ValueError:
			print "[-] %s is not a valid target!"%target
			return False
	return target

def parse_target(target):
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

def list_parser(list):
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
		ciphers = ['3des-cbc','aes128-cbc','aes192-cbc','aes256-cbc','aes128-ctr','aes192-ctr','aes256-ctr','aes128-gcm@openssh.com','aes256-gcm@openssh.com','arcfour','arcfour128','arcfour256','blowfish-cbc','cast128-cbc','chacha20-poly1305@openssh.com']
		strong_ciphers = ['chacha20-poly1305@openssh.com','aes256-gcm@openssh.com','aes128-gcm@openssh.com','aes256-ctr','aes192-ctr','aes128-ctr']
		weak_ciphers = []
	   	macs = ['hmac-md5','hmac-md5-96','hmac-ripemd160','hmac-sha1','hmac-sha1-96','hmac-sha2-256','hmac-sha2-512','umac-64','hmac-md5-etm@openssh.com','hmac-md5-96-etm@openssh.com','hmac-ripemd160-etm@openssh.com','hmac-sha1-etm@openssh.com','hmac-sha1-96-etm@openssh.com','hmac-sha2-256-etm@openssh.com','hmac-sha2-512-etm@openssh.com','umac-64-etm@openssh.com','umac-128-etm@openssh.com']
		strong_macs = ['hmac-sha2-512-etm@openssh.com','hmac-sha2-256-etm@openssh.com','umac-128','umac-128-etm@openssh.com','hmac-sha2-512','hmac-sha2-256','umac-128@openssh.com']
		weak_macs = []
		kex = ['curve25519-sha256@libssh.org','diffie-hellman-group1-sha1','diffie-hellman-group14-sha1','diffie-hellman-group-exchange-sha1','diffie-hellman-group-exchange-sha256','ecdh-sha2-nistp256','ecdh-sha2-nistp384','ecdh-sha2-nistp521','ecdsa-sha2-nistp256-cert-v01@openssh.com','ecdsa-sha2-nistp384-cert-v01@openssh.com','ecdsa-sha2-nistp521-cert-v01@openssh.com']
		strong_kex = ['curve25519-sha256@libssh.org', 'diffie-hellman-group-exchange-sha256']
		weak_kex = []
		hka = ['ecdsa-sha2-nistp256-cert-v01@openssh.com','ecdsa-sha2-nistp384-cert-v01@openssh.com','ecdsa-sha2-nistp521-cert-v01@openssh.com','ssh-ed25519-cert-v01@openssh.com','ssh-rsa-cert-v01@openssh.com','ssh-dss-cert-v01@openssh.com','ssh-rsa-cert-v00@openssh.com','ssh-dss-cert-v00@openssh.com','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521','ssh-ed25519','ssh-rsa','ssh-dss']
		strong_hka = ['ssh-rsa-cert-v01@openssh.com','ssh-ed25519-cert-v01@openssh.com','ssh-rsa-cert-v00@openssh.com','ssh-rsa','ssh-ed25519']
		weak_hka = []
		dmacs = []
		for i in macs:
			m = re.search(i, rawlist)
			if m:
				dmacs.append(i)
				if i not in strong_macs:
					weak_macs.append(i)
		dciphers = []
		for i in ciphers:
			m = re.search(i, rawlist)
			if m:
				dciphers.append(i)
				if i not in strong_ciphers:
					weak_ciphers.append(i)
		dkex = []
		for i in kex:
			m = re.search(i, rawlist)
			if m:
				dkex.append(i)
				if i not in strong_kex:
					weak_kex.append(i)
		dhka = []
		for i in hka:
			m = re.search(i, rawlist)
			if m:
				dhka.append(i)
				if i not in strong_hka:
					weak_hka.append(i)
		compression = False
		if re.search("zlib@openssh.com", rawlist):
			compression = True
		print '    [+] Detected the following ciphers: '
		print_columns(dciphers)
		print '    [+] Detected the following KEX algorithms: '
		print_columns(dkex)
		print '    [+] Detected the following MACs: '
		print_columns(dmacs)
		print '    [+] Detected the following HostKey algorithms: '
		print_columns(dhka)

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

		if weak_hka:
			print '    [+] Detected the following weak HostKey algorithms: '
			print_columns(weak_hka)
		else:
			print '    [+] No weak HostKey algorithms detected!'

		if compression == True:
			print "    [+] Compression has been enabled!"

		return True

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
