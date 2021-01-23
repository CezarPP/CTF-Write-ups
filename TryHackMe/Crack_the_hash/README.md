# Crack the hash
---
* Use hash-identifier to identify the hash
* Crack it with *hashcat* or *john*

## Level 1
---
---
---
### Hash 1
---
* Hash1: 48bb6e862e54f2a795ffc4e541caed4d
* MD5, use [crackstation.net](https://crackstation.net/)
---
### Hash 2
---
* Hash2: CBFDAC6008F9CAB4083784CBD1874F76618D2A97
* SHA1, use [crackstation.net](https://crackstation.net/)
---
### Hash 3
---
* Hash3: 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032
* SHA256, use [crackstation.net](https://crackstation.net/)
---
### Hash 4
---
* Hash4: $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom
```bash
$ hashcat -a 0 -m 3200 hash4 /usr/share/wordlists/rockyou.txt
```
---
### Hash 5
---
* Hash5: 279412f945939ba78ce0758d3fd83daa
* MD4, use [crackstation.net](https://crackstation.net/)
---
---
---
## Level 2
---
---
---
### Hash 21
---
* Hash21: F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85
* SHA256, use [crackstation.net](https://crackstation.net/)
---
### Hash 22
---
* Hash22: 1DFECA0C002AE40B8619ECF94819CC1B
* NTLM, use [crackstation.net](https://crackstation.net/)
---
### Hash 23
---
* Hash23: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.
```bash
$ hashcat -a 0 -m 1800 hash23 /usr/share/wordlists/rockyou.txt
```
---
### Hash 24
* Hash24: e5d8870e5bdd26602cab8dbe07a942c8669e56d6
* Salt: tryhackme
* Hash-identifier tells us that this is SHA1, but we can deduce that it is HMAC-SHA1 because of the provided salt.
```bash
$ echo "e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme" > hash24
$ hashcat -a 0 -m 160 hash24 /usr/share/wordlists/rockyou.txt
``` 

