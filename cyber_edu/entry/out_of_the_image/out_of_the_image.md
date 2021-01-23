Binwalk and Foremost don't yeild any results, nor does the meta-data analysis.
When trying to exctract with steghide we notice we need a password.
A tool called stegcracker, which does a 'steghide extract' and brute-forces the password with a given password list, finds the password in the classic rockyou.txt and reveals the flag.
