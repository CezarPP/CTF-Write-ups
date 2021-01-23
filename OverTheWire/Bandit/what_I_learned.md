$ sshpass -p `cat bandit0` ssh bandit0@bandit.labs.overthewire.org -p 2220
$ sort data.txt
$ uniq -u
#prints only unique lines (but only compares adjacent lines)
$ find / -size 33c -user bandit7 -group bandit6
#if something has trailing = signs (for padding) might be a hint that it is base64
$ base64 -d data.txt
$ sudo apt install bsdgames
#contains commands like
$ caesar
$ rot13

$ xxd
#creates a hexdump from a file or does the reverse
#archive tar -ceva, gzip, bzip2
#unzip tar -xvf (.tar), gunzip (.gz), bunzip2 (.bz)

$ ssh -i sshkey.private bandit14@localhost
#ssh using a given privete key
# don't specify port

$ openssl s_client -connect localhost:30001
# connect using openssl (SLL and TSL are like nc and telnet, with openssl you can see everything that is happening)

$ sshpass -p `cat level17.pass` ssh bandit18@bandit.labs.overthewire.org -p 2220 "cd /home/bandit18; cat readme"
# using sshpass to connect and run a command instantly (can be used without running anything)

$ crontab -e #edit crontab
# /etc/cron.d

# abuse the more command call by making the terminal window small so that is actually runs
# then call vim with v, :set shell = /bin/bash and then :shell

$ git log
$ git log -p
$ git show sha_hash
$ git branch
$ git branch -a
$ git checkout branch_name
$ git show --all
$ git show-ref
$ cd ./git; cat packed-refs


