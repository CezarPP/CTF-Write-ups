# LFI
---
* Parameter *page* is vulnerable to LFI

* Using it to read the /etc/passwd file gives the user *falcon*

* Reading the /etc/shadow file gives us his password hash, which can be cracked with hashcat
* This lets us connect to ssh using the username *falcon* and this password (*password09*)
```bash
$ hashcat -a 0 -m 1800 hash /usr/share/wordlists/rockyou.txt
```
* The guided tour on TryHackMe suggests reading the file */home/falcon/.ssh/id_rsa* and use this instead to connect to ssh
```bash
$ ssh -i rsa_private falcon@10.10.245.47
```

* To gain root run *sudo -l* and use the suggested GTFO bins solution to gain root


* One can use PayloadsAllTheThings to see interesting LFI payloads and interesing files to read
