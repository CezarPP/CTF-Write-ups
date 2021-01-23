# notafuzz

# We get a binary and we have to get the flag
# By using a decompiler we observe that the third time we enter input, we will have a format string vulnerability
# By printing a lot of hex values with %x we get the flag, we swap the endianness and convert the hex to ASCII

