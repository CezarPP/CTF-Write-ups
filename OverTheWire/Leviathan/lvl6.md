# Level 6
## The binary (SUID) reads from the /tmp/file.log then deletes it
## We could create /tmp/file.log and create a symbolic link to /etc/leviathan_pass/leviathan6
## ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
## Then execute ./leviathan5 and it will print the file
