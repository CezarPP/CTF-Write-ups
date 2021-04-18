#!/usr/bin/python3

from pwn import *

context.binary = './the_pass_pls'
debug = 0
# our payload xored with 0xf3 has to be equal to this (found in memory with gdb) at addr 0x555555558060
var = [0xb0, 0x8a, 0x91, 0x96, 0x81, 0xb6, 0x97, 0x86,
        0x88, 0xb0, 0xc3, 0x9d, 0x94, 0x81, 0xc7, 0x87,
        0x80, 0xac, 0x8a, 0xc3, 0x86, 0xac, 0x95, 0xc3,
        0x86, 0x9d, 0x97, 0xac, 0xc2, 0x87, 0x8e]
xor_const = 0xf3
password = 'CyberEdu{C0ngr4ts_y0u_f0und_1t}'
def build_payload():
    payload = []
    for i in var:
        payload.append(pack(i^xor_const))
    payload = b''.join(payload)
    return payload
def main():
    payload = build_payload()
    if debug == 0:
        p = process('./the_pass_pls')
        print(p.recv().decode())
        p.send(password + '\n')
        print(p.recv().decode())
    else:
        sys.stdout.buffer.write(payload + b'\r\n')

if __name__=="__main__":
    main()
