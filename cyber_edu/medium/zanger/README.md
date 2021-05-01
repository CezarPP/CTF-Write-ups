# zanger

Looking at the packet capture we see that most of the packets are UDP, except for a small fraction which are TCP.

Analyzing those, we find it weird that all are send from port 20 to ports with 1 digit numbers.

Grouping those ports together 2 at a time we get a char, and so we see that the first ones from ctf

```python
>>> bytes.fromhex('63')
b'c'
>>> bytes.fromhex('74')
b't'
>>> bytes.fromhex('66')
b'f'
>>> ord('{')
123
>>> hex(ord('{'))
'0x7b'
```

Two of the packets have port 1337 which will reprezent a 'b' for '7b', the opening and (again opening but actually) the closing brackets.

Let's use tshark to extract the port numbers.

```bash
ubuntu@ubuntu:~/Desktop/zanger$ tshark -r flag.pcap -Y 'tcp' -T text -e 'tcp.dstport' -Tfields > ports
```
Script that solves it from start to finish.
```python
#!/usr/bin/python3
import os

def main():
    os.system("tshark -r flag.pcap -Y 'tcp' -T text -e 'tcp.dstport' -Tfields > ports")
    text = open("ports", 'r').read().split('\n')[:-1]
    # split by newlines are remote the last char since it is empty
    flag = ''
    for i in range(0, len(text), 2):
        if text[i+1] == '1337':
            if i == len(text)-2:
                flag += '}'
            else: flag += '{'
        else:
            flag += bytes.fromhex(text[i] + text[i+1]).decode()
    os.system("rm ports")
    print(flag)

if __name__ == "__main__":
    main()
```