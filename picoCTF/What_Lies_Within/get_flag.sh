#!/bin/bash

stegoveritas -bruteLSB buildings.png 2>/dev/null 1>/dev/null

cd results/keepers/
strings * | grep picoCTF{ | uniq

cd ../..

rm -r results

