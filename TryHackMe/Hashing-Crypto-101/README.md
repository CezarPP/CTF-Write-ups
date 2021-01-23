# Hashes
---

## Hash1

```bash
sudo hashcat -a 0 -m 3200 -o pass1.txt hash1.txt /usr/share/wordlists/rockyou.txt
```
### First hash seems to be *Bcrypt* with code 3200 according to the *$2a* in the front
---

## Hash2

### Run *hash-identifier* on it, it tells us that it is likely *SHA-256*, with hashcat code 1400
```bash
sudo hashcat -a 0 -m 1400 -o pass2.txt hash2.txt /usr/share/wordlists/rockyou.txt
```
---

## Hash3

### We notice the *$6$* which, according to the room info, hints to *sha512crypt*, with hashcat code 1800
```bash
sudo hashcat -a 0 -m 1800 -o pass3.txt hash3.txt /usr/share/wordlists/rockyou.txt --force
```
---

## Hash4

### hash-identifier tells us that it is probably *MD5*, which it is.
### I used [https://crackstation.net/](https://crackstation.net/)
