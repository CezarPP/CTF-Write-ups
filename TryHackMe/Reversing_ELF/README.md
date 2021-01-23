# Crackme1
---
```bash
$ ./crackme1
```
## Just run it

---
---

# Crackme2
---
```bash
$ ltrace ./crackme2 mypass
```
## See that mypass gets compared to *super_secret_password* which is the flag
## Then, when I give the password to the binary, it spits out the flag

---
---

# Crackme3
---
```bash
$ strings crackme3
```
## We are presented with *ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==* this unusual string
## This is actually the flag (encoded base64), also when we give the decoded flag to the binary it prints "Correct password!"

---
---

# Crackme4
---
```bash
$ ltrace ./crackme4 pass
```
## We notice `strcmp("my_m0r3_secur3_pwd", "pass")`, easy

---
---

# Crackme5
---
```bash
$ ltrace ./crackme4 AAAA
```
## We notice 'strncmp("AAAA", "OfdlDSA|3tXb32~X3tX@sX\`4tXtz", 28)', so we have our password and flag

---
---

# Crackme6
---
## Analyzing it with a decompiler gives these functions
```cpp
undefined8 main(uint32_t argc, char **argv)
{
    char **var_10h;
    uint32_t var_4h;
    
    if (argc == 2) {
        compare_pwd(argv[1]);
    } else {
        printf("Usage : %s password\nGood luck, read the source\n", *argv);
    }
    return 0;
}
```
```cpp
void compare_pwd(char *arg1)
{
    int32_t iVar1;
    char *var_8h;
    
    iVar1 = my_secure_test((int64_t)arg1);
    if (iVar1 == 0) {
        puts("password OK");
    } else {
        printf("password \"%s\" not OK\n", arg1);
    }
    return;
}
```
```cpp

undefined8 my_secure_test(int64_t arg1)
{
    undefined8 uVar1;
    int64_t var_8h;
    
    if ((*(char *)arg1 == '\0') || (*(char *)arg1 != '1')) {
        uVar1 = 0xffffffff;
    } else {
        if ((*(char *)(arg1 + 1) == '\0') || (*(char *)(arg1 + 1) != '3')) {
            uVar1 = 0xffffffff;
        } else {
            if ((*(char *)(arg1 + 2) == '\0') || (*(char *)(arg1 + 2) != '3')) {
                uVar1 = 0xffffffff;
            } else {
                if ((*(char *)(arg1 + 3) == '\0') || (*(char *)(arg1 + 3) != '7')) {
                    uVar1 = 0xffffffff;
                } else {
                    if ((*(char *)(arg1 + 4) == '\0') || (*(char *)(arg1 + 4) != '_')) {
                        uVar1 = 0xffffffff;
                    } else {
                        if ((*(char *)(arg1 + 5) == '\0') || (*(char *)(arg1 + 5) != 'p')) {
                            uVar1 = 0xffffffff;
                        } else {
                            if ((*(char *)(arg1 + 6) == '\0') || (*(char *)(arg1 + 6) != 'w')) {
                                uVar1 = 0xffffffff;
                            } else {
                                if ((*(char *)(arg1 + 7) == '\0') || (*(char *)(arg1 + 7) != 'd')) {
                                    uVar1 = 0xffffffff;
                                } else {
                                    if (*(char *)(arg1 + 8) == '\0') {
                                        uVar1 = 0;
                                    } else {
                                        uVar1 = 0xffffffff;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return uVar1;
}
```
## The last function gives us the password *1337_pwd*

---
---

# Crackme7
---
## Analyzing the decompiled binary, we notice that if we suply *31337* we get the flag

---
---

# Crackme8
---
## By decompiling the program we get this
```cpp
iVar2 = atoi(param_2[1]);
        if (iVar2 == -0x35010ff3) {
            puts("Access granted.");
            giveFlag();
            uVar1 = 0;
        } else {
            puts("Access denied.");
            uVar1 = 1;
        }
```
## So we have to input -0x35010ff3, which is -889262067 in decimal, which gives us the flag
