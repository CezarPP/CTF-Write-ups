# Hunting

The goal is to find the flag, not to get a shell.

We get just the binary.

Here are some string we obtain.
```bash
ubuntu@ubuntu:~/Desktop/Hunting$ rabin2 -z hunting 
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002008 0x00002008 26  27   .rodata ascii prctl(PR_SET_NO_NEW_PRIVS)
1   0x00002023 0x00002023 21  22   .rodata ascii prctl(PR_SET_SECCOMP)
2   0x00002039 0x00002039 12  13   .rodata ascii /dev/urandom
0   0x00003080 0x00004080 36  37   .data   ascii HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

If we run the binary and do nothing, it just stops after like 3 seconds.

Inputing any letter into the program causes it to SEGFAULT.

Running *ltrace* tells us that it really stops after 3 seconds using the alarm() function.

```bash
ubuntu@ubuntu:~/Desktop/Hunting$ ltrace ./hunting 
__libc_start_main(0x5655b374, 1, 0xff9d45a4, 0x5655b460 <unfinished ...>
open("/dev/urandom", 0, 036777113740)                                                                                        = 3
read(3, "n\335?\214_[kl", 8)                                                                                                 = 8
close(3)                                                                                                                     = 0
srand(0x8c3fdd6e, 0xff9d44c0, 8, 0x5655b2f4)                                                                                 = 0
rand(0x8c3fdd6e, 0x6c6b5b5f, 3, 0)                                                                                           = 0x31fc9993
rand(0x8c3fdd6e, 0x6c6b5b5f, 3, 0x99930000)                                                                                  = 0x32eb150a
rand(0x8c3fdd6e, 0x6c6b5b5f, 3, 0x150a0000)                                                                                  = 0x4156399b
rand(0x8c3fdd6e, 0x6c6b5b5f, 3, 0x399b0000)                                                                                  = 0x7dd65d3e
rand(0x8c3fdd6e, 0x6c6b5b5f, 3, 0x5d3e0000)                                                                                  = 0x59cd6b36
signal(SIGALRM, 0xf7dc9170)                                                                                                  = 0
alarm(3)                                                                                                                     = 0
mmap(0x6b360000, 4096, 3, 49)                                                                                                = 0x6b360000
strcpy(0x6b360000, "HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXX"...)                                                                    = 0x6b360000
memset(0x5655e080, '\0', 37)                                                                                                 = 0x5655e080
prctl(38, 1, 0, 0)                                                                                                           = 0
prctl(22, 2, 0xff9d44c8, 0x5655b265)                                                                                         = 0
malloc(60)                                                                                                                   = 0x5798a1a0
read(0 <no return ...>
--- SIGALRM (Alarm clock) ---
+++ exited (status 14) +++
```

We see a strcpy() function that copies the flag over to the memory address. Unfortunatelly, this is random due to ASLR being enabled.

Analyzing the assembly, we notice we can put 60 bytes of code on the heap, which will then be executed (call eax , where eax points to the heap area).

We can use this code that we can run to print the flag.

We notice that during execution, the flag is copied from its place in the global memory to a place on the some memory, and then is deleted from global memory.
In consequence, we need to find that address.

We see, using *info proc mappings* that the memory is located in the file /dev/zero, which has been memory mapped.

```
	When /dev/zero is memory-mapped, e.g., with mmap, to the virtual address space, it is equivalent to using anonymous memory; i.e. memory not connected to any file. 
```
-Wikipedia

WELCOME TO EGGHUTING, this is the single most important word I needed to solve this challange. (http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)[http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf]

Using the paper, I will wrote my own shellcode, suited for the task.