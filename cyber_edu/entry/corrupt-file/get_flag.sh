#!/bin/bash

unzip flag.docx.zip 1>/dev/null 2>/dev/null
binwalk -e flag.docx 1>/dev/null 2>/dev/null
cd _flag.docx.extracted/
strings 0 | grep DCTF
