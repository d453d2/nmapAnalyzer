#!/usr/bin/python

#============================================================================================

# NMAP ANALYZER

#============================================================================================
#
# By DAS (SEDZ)
#
#============================================================================================
#
# This code requires the module 'beautiful soup' for xml parsing
# { sudo easy_install pip }
# { sudo pip install beautifulsoup4 }
# { pip install --upgrade lxml }
# should do the tick!
#
#============================================================================================


# Changes / Updates
#
# Added cache file using json     - 20/09/2016
# list host and port only option  - 20/09/2016


import sys
import os
import pprint
import time
from datetime import datetime
from bs4 import BeautifulSoup
from argparse import ArgumentParser
import json


#============================================================================================
# Arguments



# Set arguments
parser = ArgumentParser(description="\tParses NMAP XML output and summarises it, including server and service enumerated information. \
\n\tTo run: Execute the script in the parent project directory or inside the nmap results output directory 	\
\n\tThis directory needs to be named 'nmap'. \n\n\tE.G. /user/assessment/internal/{nmap}/*.xml 	\
\n\nNote: \tThis code requires the module 'BeautifulSoup' by bs4 and lxml for xml parsing, to install: 	\
\n\t{ sudo easy_install pip } 	\
\n\t{ sudo pip install beautifulsoup4 } \
\n\t{ pip install --upgrade lxml }\
\n\n ")
parser.add_argument('-i', action='store', nargs="?", dest="target_ipaddress", default="", help="Filters results for an IP address eg: [nmapAnalyzer.py -i 192.168.1.1]")
parser.add_argument('-t', action='store_true', default=False, dest='tcp', help='Returns only tcp results e.g. [nmapAnalyzer.py -t]')
parser.add_argument('-u', action='store_true', default=False, dest='udp', help='Returns only udp results e.g. [nmapAnalyzer.py -u]')
parser.add_argument('-p', action='store', nargs="?", dest="protocol", default="", help="Returns results for service type eg: [nmapAnalyzer.py -p http]")
parser.add_argument('-l', action='store_true', default=False, dest="list", help="Returns results in list format eg: [nmapAnalyzer.py -l]")
#parser.add_argument('-f', action='store', nargs="?", default="", help="Creates output files, useful for scanning and further scripting!")
parser.add_argument('--version', action='version', version="%(prog)s 2.0 written by Sedz")

#============================================================================================

# set args list parser	 				     	
args = parser.parse_args()
# set start time
starttime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
start = time.time() # measure runtime!
# current Working Dir
exedirectory = os.getcwd()
# def xmlParser args required global
#logging.basicConfig(level=logging.DEBUG, format=' %(asctime)s - %(levelname)s - %(message)s')
serviceInfo = {} # ipaddress:port, protocol, state, servicename, product, version, extrainfo - key is port number
osversionInfo = {} # hostname, onName, guessAccuracy, portDiscovered - key is ipaddress


print "\n\n"
print "----------------------"
print "|-- Nmap Analyzer  --|"
print "----------------------"
print "\n"
print "Written by Sedz, released under Creative Commons License - 2015.\n\n"
print "[!]  Looking for Nmap outputs in current project... "
print "[!]  Using '" + exedirectory + "' as project root. "
print "[!]  Execution Date/time: " + starttime 



#============================================================================================

# argument checks for tcp/udp flags
tcp = False
udp = False

if args.tcp is True and args.udp is True:
	print "----------------------------------------------------------------------------------------------"
	sys.exit("[!]  Both TCP and UDP cannot be flagged at the same time; remove both flags to return all protocols.")

elif args.tcp is True and args.udp is False:
	tcp = True
	print "[!]  Filtering by TCP Services"

elif args.udp is True and args.tcp is False:
	udp = True


# argument list
out_list = False
if args.list is True:
	print "[!]  List output has been selected."
	out_list = True


# Check for single IP address filter
all_ip = True
ip_target = ""

if str(args.target_ipaddress) != "": 
	all_ip = False
	ip_target = str(args.target_ipaddress)



# Check for single protocol e.g. http
all_proto = True
service_proto = ""

if str(args.protocol) != "" :
	all_proto = False
	service_proto = str(args.protocol)

#============================================================================================

# Check for cache file...
cache_file = "analysedFiles_nmapAlayzer.json"
if exedirectory.endswith("nmap"):

	if cache_file in os.listdir(os.getcwd()):
		print "[!]  Using cached file..."
		with open(cache_file) as f:
			data = json.load(f)
    	        file_list = data[0]
    	        for target, info in data[1].items():
    		        serviceInfo[target] = info
    	        for host, info in data[2].items():
    		        osversionInfo[host] = info


#print "service info"
#pprint.pprint(serviceInfo)
#print "osversion"
#pprint.pprint(osversionInfo)


 # run_file = list of files already handled byt previous run 
message = ""
try:
	fileList = file_list
	message = "[+]  Using data from %s previously processed Nmap files" % len(fileList)
except:
	fileList = []

#============================================================================================


# list of nmap Directories
# Global Vars
nmapFiles = []
nmapFile = ""
searchstring = ip_target+"."

# find nmap files in current project directory 
# looks for nmap directory
# if current directory is nmap it will use the current dir
if exedirectory.endswith("nmap"):

	for checkfile in os.listdir(os.getcwd()) :
		if checkfile.endswith(".xml") :
			if all_ip is False :

				if searchstring in checkfile : # uses naming convention of having the target IP in the name of the file! eg. nmap.scantype.127.0.0.1.date.xml
					nmapFiles.append(checkfile)
					
			elif all_ip is True :
				nmapFiles.append(checkfile)

	if len(nmapFiles) == 0 :
		if all_ip is False:
			print "[!]  Sorry, no nmap output files can be found for the specified target: %s " % ip_target
			print "[!]  Check file naming conventions: ip in filename?"
			sys.exit()

		else: 
			sys.exit("[!]  Sorry, no nmap output files can be found")


else:
	for directory in os.listdir(os.getcwd()) :	
		#if isinstance(directory, str): # Check if instance is type string
		#	print directory
		if directory == 'nmap':
			os.chdir(directory)

			for checkfile in os.listdir(os.getcwd()) :
				if checkfile.endswith(".xml") :
					if all_ip is False :

						if searchstring in checkfile :
							nmapFiles.append(checkfile)

					elif all_ip is True :
						nmapFiles.append(checkfile)

			if len(nmapFiles) == 0 :
				if all_ip is False:
					print "[!]  Sorry, no nmap output files can be found for the specified target: %s " % ip_target
					print "[!]  Check file naming conventions: ip in filename?"
					sys.exit()
				else: 
					sys.exit("[!]  Sorry, no nmap output files can be found")

			break # no need to look for more directories!
	


# ...located nmap files 
# could open them to check the content matches nmap!?

# now time to parse them...


###################################

# Magic happens !

###################################
count = 0
run_file = []

def xmlParser (xmlFile):

	guessAccuracy = "0"
	hostname = ""
	osName = ""
	osAccuracy = ""
	osPort = ""

	xml = open(xmlFile, 'r').read()

	bs = BeautifulSoup(xml, "xml")

	if bs.find_all("nmaprun"):
		print "[+] ",xmlFile
		fileList.append(xmlFile) # cache file list - got to here!

		global count
		count = count + 1

		for info in bs.find_all("nmaprun"):

			try:
				if info.host.status['state'] == "up":


					if bs.find_all("port") is not None:

						#print "\nService Information: "
						for ports in bs.find_all("port"):			

							if ports['portid']:

								# Add service and port information to multi-dimensional array
								newPort = str(info.address['addr'])+":"+str(ports['portid'])

								try:
									if ports.get('protocol') is not None:
										try:
											if ports.state.get('state') is not None:
												try:
													if ports.service.get('name') is not None:
														try:
															if ports.service.get('product') is not None:
																try:
																	if ports.service.get('version') is not None:
																		try:
																			if ports.service.get('extrainfo') is not None:
														
																				if newPort not in serviceInfo:

																					serviceInfo[newPort] = str(ports['portid']) , str(ports['protocol']) , str(ports.state['state']) , str(ports.service['name']) , str(ports.service['product']) , str(ports.service['version']) , str(ports.service['extrainfo']) 

																			else:
																				if newPort not in serviceInfo:
																					serviceInfo[newPort] = str(ports['portid']), str(ports['protocol']) , str(ports.state['state']) , str(ports.service['name']) , str(ports.service['product']) , str(ports.service['version']) 
																		except:
																			if newPort not in serviceInfo:
																				serviceInfo[newPort] = str(ports['portid']), str(ports['protocol']) , str(ports.state['state']) , str(ports.service['name']) , str(ports.service['product']) , str(ports.service['version']) 
											
																	else:
																		if newPort not in serviceInfo:
																			serviceInfo[newPort] = str(ports['portid']) , str(ports['protocol']) , str(ports.state['state']) , str(ports.service['name']) , str(ports.service['product'])
																except:
																	if newPort not in serviceInfo:
																		serviceInfo[newPort] = str(ports['portid']) , str(ports['protocol']) , str(ports.state['state']) , str(ports.service['name']) , str(ports.service['product'])
															
															else:
																if newPort not in serviceInfo:
																	serviceInfo[newPort] = str(ports['portid']) , str(ports['protocol']) , str(ports.state['state']) , str(ports.service['name'])
														except:
															if newPort not in serviceInfo:
																serviceInfo[newPort] = str(ports['portid']) , str(ports['protocol']) , str(ports.state['state']) , str(ports.service['name'])

													else:
														if newPort not in serviceInfo:
															serviceInfo[newPort] = str(ports['portid']) , str(ports['protocol']) , str(ports.state['state']) 
												except:
													if newPort not in serviceInfo:
														serviceInfo[newPort] = str(ports['portid']) , str(ports['protocol']) , str(ports.state['state']) 
										except: Pass
								except: Pass					


					if bs.find_all("os") is not None:

						host = str(info.address['addr'])


						for osversion in bs.find_all("os"):

							# modified to acquire hostname
							if info.hostnames.hostname['name'] is not None:
								hostname = str(info.hostnames.hostname['name'])
							elif hostname == "" or hostname == "<hostname-not-resolved>":
								hostname = "<hostname-not-resolved>"
							
							if int(osversion.osmatch['accuracy']) > int(guessAccuracy):
								guessAccuracy = osversion.osmatch['accuracy']
								osName = str(osversion.osmatch['name']) 
								osAccuracy = str(osversion.osmatch['accuracy'])
								osPort = str(osversion.portused['portid']) 

						# add host to osverison table
						if host not in osversionInfo:
							if osName != "":
								if osAccuracy != "" :
									osversionInfo[host] = hostname , osName , osAccuracy , osPort
			except:
				pass


#============================================================================================


def processNmapFiles ():

	print "[*]  Processing Nmap XML Files: "
	for n in nmapFiles:
		
		if n not in fileList:
		    nmapFile = n
		    xmlParser(nmapFile)
	if message != "":
		print message
	print "[+]  " +str(count)+ " new Nmap files processed."


def outputOSResults():
	

	print "\nTarget OS Information: \n"
	#pprint.pprint(osversionInfo)

	for target, data in osversionInfo.items():
		print "Target address: \t", target
		print "Target hostname: \t", data[0]
		print "Target OS: \t\t", data[1]
		print "Port used to ID: \t", data[3]
		print "OS Accuracy: \t\t", data[2],"%\n"
		


def outputServiceResults():

	serviceFlag = True # flag for retrieving service info.

	print "\nNmap Service Information: \n"

	if all_ip is True:
		print "Host IP\t\t\tPort_ID\t\tStatus\t\t\tProtocol\tService Information Retrieved"
		print "-----------------------------------------------------------------------------------------------------------------------"

	else: 
		print "Port_ID\t\tStatus\t\t\tProtocol\tService Information Retrieved"
		print "-----------------------------------------------------------------------------------------------------------------------"

	for target, data in sorted(serviceInfo.items()):

		if data[2] == 'open' : # filters open ports  - change to 'closed' or 'open|filtered' to see different results!

			try:
				if all_proto is True:

					if all_ip is True:


						if tcp is True and data[1] == "tcp":
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[0], "\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							# checks for service info entries and prints!	
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass

						elif udp is True and data[1] == "udp":
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[0], "\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[0], "\t\t\t", target.split(":")[1] , "\t\t" ,  data[2], "\t\t\t", data[1],  
							# checks for service info entries and prints!
							serviceFlag = False	
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass	

						elif udp is False and tcp is False:
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[0], "\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[0], "\t\t\t", target.split(":")[1] , "\t\t" ,  data[2], "\t\t\t", data[1], 
							# checks for service info entries and prints!	
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass		
						

					else:
						if tcp is True and data[1] == "tcp":
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[1] , "\t\t\t" ,  data[2], "\t\t\t", data[1], 
							# checks for service info entries and prints!	
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass

						if udp is True and data[1] == "udp":
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[1] , "\t\t\t" ,  data[2], "\t\t\t", data[1],  
							# checks for service info entries and prints!	
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass

						if udp is False and tcp is False:
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[1] , "\t\t\t" ,  data[2], "\t\t\t", data[1], 
							# checks for service info entries and prints!	
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass

					


				# protocol Specifications !!

				elif all_proto is False and data[3] == service_proto:

					if all_ip is True:

						if tcp is True and data[1] == "tcp":
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[0], "\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[0], "\t\t\t", target.split(":")[1] , "\t\t" ,  data[2], "\t\t\t", data[1], 
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass
							else:
								sys.exit("[!]  No results match that requirement!")

						elif udp is True and data[1] == "udp":
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[0], "\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[0], "\t\t\t", target.split(":")[1] , "\t\t" ,  data[2], "\t\t\t", data[1],  
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass
							else:
								sys.exit("[!]  No results match that requirement!")

						elif udp is False and tcp is False:
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[0], "\t\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[0], "\t", target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[0], "\t\t\t", target.split(":")[1] , "\t\t" ,  data[2], "\t\t\t", data[1], 
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass
							else:
								sys.exit("[!]  No results match that requirement!")		
						

					else:

						if tcp is True and data[1] == "tcp":
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[1] , "\t\t\t" ,  data[2], "\t\t\t", data[1], 
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass
							else:
								sys.exit("[!]  No results match that requirement!")

						if udp is True and data[1] == "udp":
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[1] , "\t\t\t" ,  data[2], "\t\t\t", data[1],  
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass
							else:
								sys.exit("[!]  No results match that requirement!")

						if udp is False and tcp is False:
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 			
							else:
								print target.split(":")[1], "\t\t" ,  data[2], "\t\t\t", data[1], 
							#print target.split(":")[1] , "\t\t\t" ,  data[2], "\t\t\t", data[1], 
							serviceFlag = False
							if serviceFlag is False:
								try:
									if data[4]:
										print "\t\t", data[4],
										
										try:
											if data[5]:
												print " ", data[5],

												try:
													if data[6]:
														print " ", data[6] , "\n"
													else: 
														print "\n"
												except:
													print "\n"
													pass
											else:
												print "\n"
										
										except:
											print "\n"
											pass
									
									elif data[5]: 
										print "\t\t", data[5], "\n"
									
									elif data[6]:
										print "\t\t", data[6], "\n"				
									
									else: 
										print "\n"
								
								except:
									print "\n"
									pass
							else:
								sys.exit("[!]  No results match that requirement!")		


			except:
				pass


#============================================================================================



# process nmap files
print "\n---------------------------------------------------------------------------------------------\n"

processNmapFiles()

print "\n---------------------------------------------------------------------------------------------\n"

if udp is True:
	print "[!]  Filtering by UDP"
	print "\n----------------------------------------------------------------------------------------------\n"

elif tcp is True:
	print "[!]  Filtering by TCP"
	print "\n----------------------------------------------------------------------------------------------\n"

if all_ip is False and ip_target != "":
	print "[!]  Filtering by Target: ", ip_target
	print "\n----------------------------------------------------------------------------------------------\n"

if all_proto is False:
	print "[!]  Filtering by Protocol: ", service_proto
	print "\n----------------------------------------------------------------------------------------------\n"


outputOSResults()


# checks for output args (list of hosts and ports)
if out_list is False:
	outputServiceResults()
else:
	print "\nNmap up hosts & open ports list: \n"
	# check for host specific args
	# single ip,
	if all_ip is False:
		# all protocols
		if all_proto is True:
			for target, data in sorted(serviceInfo.items()):
				if target.split(":")[0] == ip_target:
					if len(target.split(":")[0]) <= 13:
						print target.split(":")[0], "\t\t", target.split(":")[1]
					elif len(target.split(":")[0]) == 14:
						print target.split(":")[0], "\t\t", target.split(":")[1]			
					else:
						print target.split(":")[0], "\t", target.split(":")[1]
		# spcific protocol
		else: 
			for target, data in sorted(serviceInfo.items()):
				if target.split(":")[0] == ip_target:
					try:
						if data[3] == service_proto:
							if len(target.split(":")[0]) <= 13:
								print target.split(":")[0], "\t\t", target.split(":")[1]
							elif len(target.split(":")[0]) == 14:
								print target.split(":")[0], "\t\t", target.split(":")[1]			
							else:
								print target.split(":")[0], "\t", target.split(":")[1]
					except:
						pass
	# all ips
	else:
		# all protocols
		if all_proto is True:
			for target, data in sorted(serviceInfo.items()):
				if len(target.split(":")[0]) <= 13:
					print target.split(":")[0], "\t\t", target.split(":")[1]
				elif len(target.split(":")[0]) == 14:
					print target.split(":")[0], "\t\t", target.split(":")[1]			
				else:
					print target.split(":")[0], "\t", target.split(":")[1]
		# spcific protocol
		else:
			for target, data in sorted(serviceInfo.items()):
				try:
					if data[3] == service_proto:
						if len(target.split(":")[0]) <= 13:
							print target.split(":")[0], "\t\t", target.split(":")[1]
						elif len(target.split(":")[0]) == 14:
							print target.split(":")[0], "\t\t", target.split(":")[1]			
						else:
							print target.split(":")[0], "\t", target.split(":")[1]
				except:
					pass



# Write out cache file
# set earlier cache_file = "analysedFiles_nmapAlayzer.json"
if cache_file in os.listdir(os.getcwd()):
	os.remove(cache_file)
with open(cache_file, 'a') as f:
	jsonOut = []
	jsonOut.append(fileList)
	jsonOut.append(serviceInfo)
	jsonOut.append(osversionInfo)
	f.write(json.dumps(jsonOut)) # processed files
	f.close()



print "\n\n-----------------------------------------------------------------------------------------------------------------------\n"  

cache_addr = exedirectory+"/"+cache_file
print "[+]  Cache file saved: '%s' " % cache_addr 

print "\n---------------------------------------------------------------------------------------------\n"
print "[!]  Runtime: %.2f seconds \n" %(time.time() - start)
print "---------------------------------------------------------------------------------------------\n"

		










