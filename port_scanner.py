#! /usr/bin/python

import os
import sys
from socket import *
from threading import *
import argparse
import pyfiglet
from termcolor import colored

class MyParser(argparse.ArgumentParser):
	"""Override error method to exit programm on error"""
	def error(self, message):
		sys.stderr.write("error: %s\n" % message)
		self.print_help()
		sys.exit(2)


class Range(argparse.Action):
	def __init__(self, firstport=None, lastport=None, *args, **kwargs):
		self.min = firstport
		self.max = lastport 
		super(Range, self).__init__(*args, **kwargs)

	def __call__(self, parser, namespace, value, option_string=None):

		if not(self.min <= value[0] <=self.max) or not (self.min <= value[1] <= self.max):
			msg = "invalid choice: %r (choose from [%d-%d])" % (value, self.min, self.max)
			raise argparse.ArgumentError(self, msg)
		setattr(namespace, self.dest, value)


def setUpArgsParser():
	parser = MyParser(description="Scans multiple ports of host")
	parser.add_argument("host", help="Specify target host")
	parser.add_argument("-p", "--ports", help="Specify target ports separated by comma")
	parser.add_argument("-pr", "--portrange", nargs=2, type=int, metavar=("firstport", "lastport"), firstport=1, lastport=65536,\
							action=Range, default=22,\
							help="Define range of ports separated by space between 1 and 65535")
	parser.add_argument("-b", "--banner", action="store_true")
	parser.add_argument("-vf", "--vulsoftfile", help="Specify destination to txt file with vulnerable os soft")
	args = parser.parse_args()
	return args

class FileAccess:
	def __init__(self):
		pass

	@staticmethod
	def checkFileAccess(filename):
		if not os.path.isfile(filename):
			print("[-] File doesn't exist")
			exit(0)
		if not os.access(filename, os.R_OK):
			print("[-] Access to file denied")
			exit(0)

class Utils:

	def __init__(self):
		pass

	@staticmethod
	def convertToInt(strNum):
		try:
			return int(strNum)
		except ValueError:
			print("Not a number: %s" % strNum)

class MyPortScanner:

	def __init__(self, tgtHost, tgtPorts):
		self.tgtHost = tgtHost
		self.tgtPorts = tgtPorts

	@staticmethod
	def getUsersPorts(tgtPorts):
		return list(map(Utils.convertToInt, tgtPorts.split(",")))

	@staticmethod
	def getPortsByRange(firstport, lastport):
		return list(range(firstport, lastport+1))

	def _getIp(self):
		try:
			tgtIp = gethostbyname(self.tgtHost)
			return tgtIp
		except:
			print("Unknown Host %s" % tgtIp)

	def _getHostName(self, tgtIp):
		try:
			tgtHostNameTuple = gethostbyaddr(tgtIp)
			return tgtHostNameTuple[0]
		except:
			print("Unknown Ip Target" % tgtIp)

	def _getValidHost(self):
		tgtIp = self._getIp()
		if tgtIp:
			tgtHostName = self._getHostName(tgtIp)
			print("[+] Scan Results for: %s" % tgtHostName)
			return tgtHostName

	def scanPorts(self):
		tgtIp = self._getIp()
		print("[+] Target IP-addres is %s" % tgtIp)
		for tgtPort in self.tgtPorts:
			t = Thread(target=self._connToPort, args=(tgtIp, tgtPort))
			t.start()

	def _connToPort(self, tgtIp, tgtPort):
		setdefaulttimeout(2)
		sock = socket(AF_INET, SOCK_STREAM) # ip4 tcp connection
		try:
			connIndicator = sock.connect_ex((tgtIp, tgtPort))
			if connIndicator == 0: # 0 is an indicator of successfull connection
				print(colored("[+] %s/tcp Open" %  tgtPort, "green"))
			else:
				print(colored("[-] %s/tcp Closed" % tgtPort, "red"))
		except Exception as e:
			print(e)


class MyPortBannerScanner(MyPortScanner):
	def __init__(self, tgtHost, tgtPorts):
		super().__init__(tgtHost, tgtPorts)

	def _connToPort(self, tgtIp, tgtPort):
		try:
			setdefaulttimeout(2)
			sock = socket()
			connIndicator = sock.connect_ex((tgtIp, tgtPort))
			if connIndicator == 0: 
				banner = sock.recv(1024)
				if banner:
					print("[+] %s/tcp : %s" %  (tgtPort, banner.decode("UTF-8")))

			else:
				print("[-] %s/tcp is Closed" % tgtPort)
		except Exception as e:
			print(e)
			return


class MyPortBannerVulScanner(MyPortScanner):
	def __init__(self, tgtHost, tgtPorts, filename):
		super().__init__(tgtHost, tgtPorts)
		self.filename = filename

	def _connToPort(self, tgtIp, tgtPort):
		try:
			setdefaulttimeout(2)
			sock = socket()
			connIndicator = sock.connect_ex((tgtIp, tgtPort))
			if connIndicator == 0: 
				banner = sock.recv(1024)
				if banner:
					print("[+] %s/tcp : %s" %  (tgtPort, banner.decode("UTF-8")))
					self.checkVulns(banner)
			else:
				print("[-] %s/tcp is Closed" % tgtPort)
		except Exception as e:
			print(e)
			return

	def checkVulns(self, banner):
		with open(self.filename) as f:
			for line in f.readlines():
				if line.strip("/n") in banner.decode("UTF-8"):
					print(colored("[+] Server is vulnarable %s " % banner.decode("UTF-8").strip("/n"), "red"))


def main():
	args = setUpArgsParser()

	tgtHost = args.host
	tgtPorts = args.ports
	portRange = args.portrange
	banner = args.banner
	vulsoftfile = args.vulsoftfile


	ascii_logo = pyfiglet.figlet_format("PORT SCAN")
	print(ascii_logo)

	if vulsoftfile:
		FileAccess.checkFileAccess(vulsoftfile)
		if tgtPorts:
			tgtPorts = MyPortBannerVulScanner.getUsersPorts(tgtPorts)
			portScanner = MyPortBannerVulScanner(tgtHost, tgtPorts, vulsoftfile)
		elif portRange: 
			portRange = MyPortBannerVulScanner.getPortsByRange(*portRange)
			portScanner = MyPortBannerVulScanner(tgtHost, portRange, vulsoftfile)
		portScanner.scanPorts()

	elif banner:
		if tgtPorts:
			tgtPorts = MyPortBannerScanner.getUsersPorts(tgtPorts)
			portScanner = MyPortBannerScanner(tgtHost, tgtPorts)
		elif portRange: 
			portRange = MyPortBannerScanner.getPortsByRange(*portRange)
			portScanner = MyPortBannerScanner(tgtHost, portRange)
		portScanner.scanPorts()
	else:

		if tgtPorts:
			tgtPorts = MyPortScanner.getUsersPorts(tgtPorts)
			portScanner = MyPortScanner(tgtHost, tgtPorts)
		elif portRange: 
			portRange = MyPortScanner.getPortsByRange(*portRange)
			portScanner = MyPortScanner(tgtHost, portRange)
		portScanner.scanPorts()

if __name__ == "__main__":
	main()
