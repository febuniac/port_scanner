#!/usr/bin/python

# Importing the modules
import socket # Used to create a socket connection
import sys
import time
import datetime
import argparse # Used to parse arguments 
import os
from termcolor import colored
flag = 0  
#___________________________________________________________________________________________________
os.system('clear') # Clear the console window
#just creating lines
line = "_" * 80 
line2 = "." * 50

#Descritpion of the program when user enters -h
desc = line+'''\n This program is a Port Scanner:\n
HOW TO USE: python Buniac_portscanner.py example.com start_door end_door\n
The above example will scan the host \'example.com\' from start_port to end_port.
To scan most common ports, use: python port_scanner.py example.com\n'''+line+"\n"

parser = argparse.ArgumentParser(prog='Buniac_portscanner',description = desc, formatter_class=argparse.RawTextHelpFormatter)#for help of usage
parser.add_argument('host', metavar='HOST', help='Host name you want to scan')
parser.add_argument('startport', metavar='Init_DOOR', nargs='?', help='Start scanning from this port')# args.startpoint corresponds to the first port we will scan
parser.add_argument('endport', metavar='End_DOOR', nargs='?',help='Scan until this port')# args.endport corresponds to the last port
args = parser.parse_args()
 
host = args.host # The host name to scan for open ports
ip = socket.gethostbyname(host) # Converts the host name into IP address 
 #___________________________________________________________________________________________________

# Checks if starting port and ending port are defined [if not defined  scan over most common_ports]
if (args.startport) and args.endport :
	# If this condition is true, the script will scan over this port range from start to end
	start_port = int(args.startport)
	end_port = int(args.endport)
else:
	# In this case, the script will scan the most common ports.
	flag = 1
	
 
open_ports = []  # This list is used to hold the open ports
 
# This dictionary contains the most popular ports used [key = port number and value is the service of the door]
common_ports = {
    #TCP and UDP
    '53': 'DNS',
    '137': 'NETBIOS-NS',
	'138': 'NETBIOS-DGM',
	'139': 'NETBIOS-SSN',
    '161': 'SNMP',
	'162': 'SNMP',
    '389': 'LDAP',
    '636': 'LDAPS',
    #UDP
    '67': 'DHCP',
    '68': 'DHCP',
    '69': 'TFTP',
    '123': 'NTP',
    #TCP
	'21': 'FTP',
	'22': 'SSH',
	'23': 'TELNET',
	'25': 'SMTP',
	'80': 'HTTP',
	'109': 'POP2',
	'110': 'POP3',
	'143': 'IMAP',
	'156': 'SQL-SERVER',
    '179': 'BGP',
	'443': 'HTTPS',
	'546': 'DHCP-CLIENT',
	'547': 'DHCP-SERVER',
    '989': 'TLS',
    '990': 'SSL',
	'995': 'POP3-SSL',
	'993': 'IMAP-SSL',
	'2086': 'WHM/CPANEL',
	'2087': 'WHM/CPANEL',
	'2082': 'CPANEL',
	'2083': 'CPANEL',
	'3306': 'MYSQL',
	'8443': 'PLESK',
	'10000': 'VIRTUALMIN/WEBMIN'
}
 
starting_time = time.time() # Get the time at which the scan was started
print (line2)
print colored("\tBuniac's DOOR SCANNER","white","on_grey")
print (line2)
 
if (flag): # The flag is set, that means the user did not provide any ports as argument
	print colored("No ports were defined! \n  Scanning for most common ports on %s" % (host),"blue","on_cyan")
else:
	# The user did specify a port range to scan
	print colored("Scanning %s from port %s - %s: " % (host, start_port, end_port),"blue","on_cyan")
print ("Scanning starting time: %s" %(time.strftime("%I:%M:%S %p")))
 
 #___________________________________________________________________________________________________
 
# This is the function that will connect to a port and will check if it is open or closed
def check_portUDP(host, port, result = 1):# The function takes 3 arguments[host : the IP to scan, port : the port number to connect]
	try:
		# Creating a socket object
		socket1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		# Setting socket timeout so that the socket does not wait forever to complete  a connection
		socket1.settimeout(1)
		# Connect to the socket -- if the connection was successful, that means the port is open, and the output 'r' will be zero
		out = socket1.connect_ex((host, port))	
		if out == 0:
			result = out 
		socket1.close() # closing the socket
	except Exception, e:
		pass
	return result # returns the result of the scan.

#___________________________________________________________________________________________________

def check_portTCP(host, port, result = 1):# The function takes 3 arguments[host : the IP to scan, port : the port number to connect]
	try:
		# Creating a socket object
		socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Setting socket timeout so that the socket does not wait forever to complete  a connection
		socket1.settimeout(0.5)
		# Connect to the socket -- if the connection was successful, that means the port is open, and the output 'r' will be zero
		out = socket1.connect_ex((host, port))	
		if out == 0:
			result = out 
		socket1.close() # closing the socket
	except Exception, e:
		pass
	return result # returns the result of the scan.
 
#___________________________________________________________________________________________________

# This function reads the dictionary of ports and services and hecks for the service name corresponding to a port.
def get_service(port):
	port = str(port) # converts the int to string
	if port in common_ports: # check if the port is available in the common ports dictionary
		return common_ports[port] # returns the service name if available
	else:
		return 0 # return 0 if no service is identified
 
try:
	print colored("Scan in progress..",'red', attrs=['reverse', 'blink'])
	print colored("Connecting to Port: ","yellow",attrs=['bold'])
 
	if flag: # The flag is set, means the user did not give any port range
		for p in sorted(common_ports): # So we will scan the common ports. 
			sys.stdout.flush() # flush the stdout buffer.
			p = int(p)
			service = get_service(p)
			if not service: # The service is not in the dictionary
				service = "Unknown service"
			print (p,service)
			responseTCP = check_portTCP(host, p) # call the function to connect to the port
			responseUDP = check_portUDP(host, p)
			#___________________________________________________________________________________________________

			if responseTCP == 0  : # The port TCP is open
				open_ports.append(p) # append it to the list of open ports

				sys.stdout.write('\b' * len(str(p))) # This is just used to clear the port number displayed. 
		
	#___________________________________________________________________________________________________
	
	else:
		
		# The user did provide a port range, now we have to scan through that range 
		for p in range(start_port, end_port+1):
			sys.stdout.flush()
			p = int(p)
			service = get_service(p)
			if not service: # The service is not in the disctionary
				service = "Unknown service"
			print (p,service)
			responseTCP = check_portTCP(host, p) # call the function to connect to the port
			responseUDP = check_portUDP(host, p) # call the function to connect to the port
			#___________________________________________________________________________________________________
			if responseTCP == 0 : # Port TCP is open
				open_ports.append(p) # Append to the list of open ports
			
			# 	open_ports.append(p) # Append to the list of open ports
			if not p == end_port:
				sys.stdout.write('\b' * len(str(p)))
 #___________________________________________________________________________________________________

	print ("\nScanning completion time: %s" %(time.strftime("%I:%M:%S %p")))
	ending_time = time.time()
	total_time = ending_time - starting_time # Calculating the total time used to scan
	print (line2)
	print ("\tScan Report in host: %s" %(host))
	print (line2)
	if total_time <= 60:
		total_time = str(round(total_time, 2))
		print ("Scan Took %s seconds" %(total_time))
	else:
		total_time = total_time / 60
		print colored("Scan Took %s Minutes" %(total_time))
		
	if open_ports: # There are open ports available
		print "Open Ports: "
		for i in sorted(open_ports):
			service = get_service(i)
			if not service: # The service is not in the dictionary, is not known
				service = "Unknown service"
			print colored("\t%s %s: Open" % (i, service),"green",attrs=['bold'])
	else:
		# No open ports were found
		print colored("Sorry, No open ports found!!","red",attrs=['bold'])
 
except KeyboardInterrupt: # If user press "Ctrl+C", it will show the following error
	print ("You pressed Ctrl+C. Exiting ")		
	sys.exit(1)

    