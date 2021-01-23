# Gogu
```
gdb-peda$ catch syscall write
gdb-peda$ r
gdb-peda$ c                                      x5
gdb-peda$ vmmap
gdb-peda$ dump memory memorie 0x00400000 0x00484000
gdb-peda$ dump memory memorie2 0x00484000 0x00517000

$ find . -name "memorie*" | cut -d '/' -f 2 | xargs strings | grep ctf{ | uniq
```
