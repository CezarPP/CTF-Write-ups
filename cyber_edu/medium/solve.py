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