#!/bin/bash
unzip chall.jpeg.zip

foremost chall.jpeg
cd output/
cd png/
zbarimg -q 00000216.png
