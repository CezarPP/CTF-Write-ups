First we notice that we have to set the start argument with GET in order to be able to see the spoils of our work.

We notice that the escapeshellcmd() doesn't escape '-' signs, so we can add arguments to the find function. But which ones would be useful?

The escapeshellcmd() function doesn't remove the forbidden chars, instead it uses '\' to escape their meaning for the command line.

On a close study of the man page of find, we notice an option called -exec, which executes an arbitrary command and has to be followed by an escaped semicolon '\;'.

Thankfully our function escapes it automatically if we provide it without a '\'.

Next we notice that we have almost arbitrary command execution (or commands should't use any of the characters escaped by the php function).

We can provide the url: http://IP:PORT/?start=ceva&arg=ceva%20-or%20-exec%20find%20/%20-fprint%20my_file%20;
Which will write all of the filesystem to my_file, which we can access with the url: http://IP:PORT/my_file
We want to print our output to a file because of the 'hashing' that is applied to the output printed with echo and which would require a brute-force decode, which is hard to get right and the results are not satisafactory (I tried for a couple hours)

Searching for a flag file in the file system we find /var/www/html/flag
We can't print it with cat because of the base64 uppercase 'hashing', but we can move it to the current directory with this url: http://35.242.239.180:30233/?start=ceva&arg=ceva%20-or%20-exec%20cp%20/var/www/html/flag%20.%20;
Then we can access it by simply accessing the url: http://IP:PORT/flag





