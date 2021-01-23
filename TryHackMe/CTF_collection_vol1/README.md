# CTF collection Vol.1

Flag format: THM{flag}

## Task 2
```bash
$ echo "VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==" | base64 -d
```
---
## Task 3
```bash
$ exiftool Findme.jpg
```
---
## Task 4
* The password is empty
```bash
$ steghide --extract -q -p '' -sf Extinction.jpg; cat Final_message.txt | grep THM
```
---
## Task 5
* Highlight the text near the task
---
## Task 6
```bash
$ zbarimg QR.png 2>/dev/null | grep THM
```
---
## Task 7
```bash
$ strings hello.hello | grep THM
```
---
## Task 8
* Base58, use [cyberchef](https://gchq.github.io/CyberChef/)
---
## Task 9
```bash
$ echo "MAF{atbe_max_vtxltk}" | caesar
```
---
## Task 10
* Find in the HTML
---
## Task 11
* Restore the PNG file header with something like *hexedit*
---
## Task 12
* Find the flag [here](https://www.reddit.com/r/tryhackme/comments/eizxaq/new_room_coming_soon/)
---
## Task 13
* Brainfuck
---
## Task 14
* Convert to hex, then XOR the 2
```cpp
#include <bits/stdc++.h>
using namespace std;
char s1[]="DX]k#hs|e%!f#O bm";//already in hex
char s2[]="1010101010101010101010101010101010";//10 -> 16 in hex
int main()
{
        int n = strlen(s1);
        printf("%d\n", n);

        for(int i=0; i<n; i++)
                s1[i] = char(int(s1[i])^16);
        printf("%s", s1);
}
```
---
## Task 15
* Use binwalk
---
## Task 16
* Stegoveritas and look at autocontrast
---
## Task 17
* Scan and listen for the flag...
---
## Task 18
* Wayback machine, see how sites looked in the past, cool
---
## Task 19
* Manualy find the key (THM), or
* [vingere solver](https://www.guballa.de/vigenere-solver)
---
## Task 20
* Whole number to hex, then hex to ASCII
---
## Task 21
* Find http stream
---


