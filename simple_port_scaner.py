#! /usr/bin/python

import socket
import argparse

parser = argparse.ArgumentParser(description="Scan ports")
parser.add_argument('host', help="Enter host")
parser.add_argument('-port', type=int, help="Enter port")
args = parser.parse_args()


socket.setdefaulttimeout(1)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = args.host
port =  args.port

def portScan(port):
	connectIndicator = sock.connect_ex((host, port))
	if connectIndicator == 0: # operation succeeded
		print("Port %s is open" % port)
	else: # may get error indicator
		print("Port %s is closed" % port)

portScan(port)
