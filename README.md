# nmapAnalyzer
script to view nmap results. parses and displays various queries and output forms.


# What does it do?
 - It takes various nmap xml output files and provides fast analysis of the scan results
 - It creates a json cache file of info already parsed from previous runs to save re-running.
 - can filter results based on target, protocol, service type
 - can produce list based output for piping to further tools or full report including host details (if nmaps -O was used.) 


# Requirements & Setup
A couple of Python modules are needed to run the script, including python 2.x. 
 - pip: sudo easy_install pip
 - bs4: sudo pip install beautifulsoup4
 - lxml: pip install --upgrade lxml
 - if you dont have lxml you may need to install this too 
 - Lastly chmod +x nmapAnalyzer_2.0.py (mk it exec)

```
$./nmapAnalyzer_2.0.py -h
usage: nmapAnalyzer_2.0.py [-h] [-i [TARGET_IPADDRESS]] [-t] [-u]
                           [-p [PROTOCOL]] [-l] [--version]

Parses NMAP XML output and summarises it, including server and service
enumerated information. To run: Execute the script in the parent project
directory or inside the nmap results output directory This directory needs to
be named 'nmap'. E.G. /user/assessment/internal/{nmap}/*.xml Note: This code
requires the module 'BeautifulSoup' by bs4 and lxml for xml parsing, to
install: { sudo easy_install pip } { sudo pip install beautifulsoup4 } { pip
install --upgrade lxml }

optional arguments:
  -h, --help            show this help message and exit
  -i [TARGET_IPADDRESS]
                        Filters results for an IP address eg: [nmapAnalyzer.py
                        -i 192.168.1.1]
  -t                    Returns only tcp results e.g. [nmapAnalyzer.py -t]
  -u                    Returns only udp results e.g. [nmapAnalyzer.py -u]
  -p [PROTOCOL]         Returns results for service type eg: [nmapAnalyzer.py
                        -p http]
  -l                    Returns results in list format eg: [nmapAnalyzer.py
                        -l]
  --version             show program's version number and exit
  ```
  

# Usages:


Step 1: FYI

  The parser is designed to handle outputted nmap xml files.
  These need to be in a directory 'nmap'.
  If you wish to use the '-i' flag you will need to ensure that the target is in the file name of the xml.

Step 2: Run nmap
	As above:
	
	sudo nmap -sSV -v -T5 -O --osscan-guess 127.0.0.1 -p1-1000 -oX nmap.syn-vers.127.0.0.1

Step 3: Run the analyzer
	
	cd nmap
	./nmapAnalyzer_2.0.py 
```
----------------------
|-- Nmap Analyzer  --|
----------------------


Written by Sedz, released under Creative Commons License - 2015.


[!]  Looking for Nmap outputs in current project... 
[!]  Using '~/Infrastructure/active-recon/nmap' as project root. 
[!]  Execution Date/time: 2016-09-22 17:54:42
[!]  Using cached file...

---------------------------------------------------------------------------------------------

[*]  Processing Nmap XML Files: 
[+]  Using data from 3 previously processed Nmap files
[+]  0 new Nmap files processed.

---------------------------------------------------------------------------------------------


Target OS Information: 

Target address: 	127.0.0.1
Target hostname: 	localhost
Target OS: 		    Apple Mac OS X 10.10 (Yosemite) - 10.11 (El Capitan) (Darwin 14.0.0 - 15.0.0)
Port used to ID: 	631
OS Accuracy: 		 100 %


Nmap Service Information: 

Host IP			Port_ID		Status			Protocol	Service Information Retrieved
-----------------------------------------------------------------------------------------------------------------------

127.0.0.1 		17600 		open 			tcp 		Tornado httpd   4.2 

127.0.0.1 		17603 		open 			tcp 

127.0.0.1 		29754 		open 			tcp 

127.0.0.1 		631 		  open 			tcp 		CUPS   2.1 



-----------------------------------------------------------------------------------------------------------------------

[+]  Cache file saved: '~/Infrastructure/active-recon/nmap/analysedFiles_nmapAlayzer.json' 

---------------------------------------------------------------------------------------------

[!]  Runtime: 0.00 seconds 

---------------------------------------------------------------------------------------------

```
Filter by target IP, tcp ports and http protocol services

```
./nmapAnalyzer_2.0.py -i 127.0.0.1 -t -p http	




----------------------
|-- Nmap Analyzer  --|
----------------------


Written by Sedz, released under Creative Commons License - 2015.


[!]  Looking for Nmap outputs in current project... 
[!]  Using '~/Infrastructure/active-recon/nmap' as project root. 
[!]  Execution Date/time: 2016-09-22 17:57:34
[!]  Filtering by TCP Services
[!]  Using cached file...

---------------------------------------------------------------------------------------------

[*]  Processing Nmap XML Files: 
[+]  Using data from 3 previously processed Nmap files
[+]  0 new Nmap files processed.

---------------------------------------------------------------------------------------------

[!]  Filtering by TCP

----------------------------------------------------------------------------------------------

[!]  Filtering by Target:  127.0.0.1

----------------------------------------------------------------------------------------------

[!]  Filtering by Protocol:  http

----------------------------------------------------------------------------------------------


Target OS Information: 

Target address: 	127.0.0.1
Target hostname: 	localhost
Target OS: 		    Apple Mac OS X 10.10 (Yosemite) - 10.11 (El Capitan) (Darwin 14.0.0 - 15.0.0)
Port used to ID: 	631
OS Accuracy: 		 100 %


Nmap Service Information: 

Port_ID		Status			Protocol	Service Information Retrieved
-----------------------------------------------------------------------------------------------------------------------
17600 		open 			tcp 		Tornado httpd   4.2 



-----------------------------------------------------------------------------------------------------------------------

[+]  Cache file saved: '~/Infrastructure/active-recon/nmap/analysedFiles_nmapAlayzer.json' 

---------------------------------------------------------------------------------------------

[!]  Runtime: 0.00 seconds 

---------------------------------------------------------------------------------------------

```

Last example, as list form (useful for other tools...)

```
./nmapAnalyzer_2.0.py -i 127.0.0.1 -l -t




----------------------
|-- Nmap Analyzer  --|
----------------------


Written by Sedz, released under Creative Commons License - 2015.


[!]  Looking for Nmap outputs in current project... 
[!]  Using '~/Infrastructure/active-recon/nmap' as project root. 
[!]  Execution Date/time: 2016-09-22 17:59:05
[!]  Filtering by TCP Services
[!]  List output has been selected.
[!]  Using cached file...

---------------------------------------------------------------------------------------------

[*]  Processing Nmap XML Files: 
[+]  Using data from 3 previously processed Nmap files
[+]  0 new Nmap files processed.

---------------------------------------------------------------------------------------------

[!]  Filtering by TCP

----------------------------------------------------------------------------------------------

[!]  Filtering by Target:  127.0.0.1

----------------------------------------------------------------------------------------------


Target OS Information: 

Target address: 	127.0.0.1
Target hostname: 	localhost
Target OS: 		    Apple Mac OS X 10.10 (Yosemite) - 10.11 (El Capitan) (Darwin 14.0.0 - 15.0.0)
Port used to ID: 	631
OS Accuracy: 		 100 %


Nmap up hosts & open ports list: 

127.0.0.1 		17600
127.0.0.1 		17603
127.0.0.1 		29754
127.0.0.1 		631


-----------------------------------------------------------------------------------------------------------------------

[+]  Cache file saved: '~/Infrastructure/active-recon/nmap/analysedFiles_nmapAlayzer.json' 

---------------------------------------------------------------------------------------------

[!]  Runtime: 0.00 seconds 

---------------------------------------------------------------------------------------------	

```
Hope you enjoy using it.


