# Pickle Rick

```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Pickle_Rick$ nmap -p- 10.10.239.225 | tee open_ports
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-26 18:58 UTC
Nmap scan report for 10.10.239.225
Host is up (0.085s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 368.10 seconds
```

```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Pickle_Rick$ nmap -p22,80 -sC -sV 10.10.239.225 | tee nmap_scan
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-26 19:13 UTC
Nmap scan report for 10.10.239.225
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:b0:95:de:1c:7a:9a:17:02:d2:ff:cb:b6:42:79:e1 (RSA)
|   256 8d:be:3c:b7:80:44:72:de:db:ea:d8:46:75:90:e7:9b (ECDSA)
|_  256 74:f9:bd:c1:1d:d1:fb:6b:87:83:49:c9:a8:22:1a:89 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.19 seconds
```

```
  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->
```

* Username: R1ckRul3s

Gobuster finds the page *login.php*.

Use that username and the password from *robots.txt* to log in.

We have a command line, where we can't execute *cat* or *head*, but we can use *grep . file* to cat out a file or *while read line; do echo $line; done < ceva.txt*.

The first ingredient is in the current dir. 

The second one can be found by dumping the whole filesystem and seaching for *'ingr'* and it is in */home/rick/second ingredients*.

I gueesed that the third one might be in */root* and I guessed correctly.

Getting a nc reverse shell didn't seem to work, but we could have gotten a reverse shell using python3


