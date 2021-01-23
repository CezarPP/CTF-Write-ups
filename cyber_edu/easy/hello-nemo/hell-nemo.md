# hello-nemo
## We are given a capture file and told to find the flag
## First I notice that there are file being accessed and send.
## Then I see a file flag.zip which seems to be transfered, which means I can have it
## After finding this flag.zip, I followed the tcp-stream, and saved the file as an obj(raw)
## When I wanted to extract the context I noticed that it was password protected
## Thankfully, when I was looking through the capture, I noticed another file called password.txt
## Also I noticed the command 'cat *pass* > password.txt" being sent through TCP (I used a filter like *tcp contains "password.txt"* in wireshark), which gave me the password
