# Inclusion

## Simple file inclusion vulnerability

## http://*IP*/article?name=lfiattack
## This is a sample link, presumably the "name" parameter is sent through GET to php, which provides the file from the system
## We can try to cat /etc/passwd
## http://*IP*article?name=../../../../etc/passwd
## We notice a comment containing the password for falconfeast ssh
## We connect with user falconfeast to ssh, using the found password
## In his folder we find the user.txt flag
## To obtain root we run sudo -l
## We notice socat has root privileges
## So we search GTFO bins for the command to gain a shell, which was $sudo socat stdin exec:/bin/sh
## In the /root folder we find the root.txt flag
