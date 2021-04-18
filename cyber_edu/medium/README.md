# alien-console

The console uses some sort of cypher to encode the text

```bash
kali@kali:~/Desktop/alien-console$ nc 35.234.100.160 32547
Welcome, enter text here and we will secure it: aaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaa
0215071a540359525905035500535052035004530251515003040756505853565053025405530357580057580704505057045203570351570300540700575454540500511c
```

By sending ctf{ we get some zeros, so maybe the input is xored with the flag. We have to input chars until we get a 
```bash
kali@kali:~/Desktop/alien-console$ nc 35.234.100.160 32547
Welcome, enter text here and we will secure it: ctf{
ctf{
0000000056015b505b07015702515250015206510053535201060554525a515452510056075101555a02555a0506525255065001550153550102560502555656560702531e
```

```bash
kali@kali:~/Desktop/alien-console$ echo -e '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' | nc 35.234.100.160 32547
^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@^@
Welcome, enter text here and we will secure it: Traceback (most recent call last):
  File "server.py", line 10, in <module>
    msg = raw_input("Welcome, enter text here and we will secure it: ")
EOFError
```
We can't send null chars, that would have been easy, but we can deduce the flag either by guessing each char, or by sending all a's and then xoring the output with all a's.

```bash
kali@kali:~/Desktop/alien-console$ nc 35.234.100.160 32547
Welcome, enter text here and we will secure it: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0215071a540359525905035500535052035004530251515003040756505853565053025405530357580057580704505057045203570351570300540700575454540500511c02020202020202020202020202020202020202020202020202020202
```
It xores only for the size of the flag, then sends hex 20.

```bash
#!/usr/bin/python3

from pwn import *

IP = '35.234.100.160'
port = 32547
def main():
    r = remote(IP, port)
    r.recvuntil(': ')
    r.sendline('a'*69)
    # we get out input echoed back first
    r.recvuntil('\r\n')
    data = r.recvuntil('\r\n', drop=True)
    
    data = data.decode()
    data = bytes.fromhex(data)
    data = xor(data, b'a')
    print(data.decode())

if __name__ == "__main__":
    main()
```
This gets the flag, I initally used cyberchef for getting data from hex and xoring but then I decided to make a script.