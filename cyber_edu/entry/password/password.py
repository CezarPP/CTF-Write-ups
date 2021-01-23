######################################33
######I got this code using an online decompiler to decompile the .pyc file
###############just print the flag
"""
a = 'DCTF{09fa'
c = '4d3142a6a'
b = '7ab70e9aa'
f = '1929d62e0'
g = '805934d86'
d = 'd4b55ea5b'
e = '1a436b536'
h = '59eadd}'
flag = a + b + c + d + e + f + g + h
password = 'Pass999990000!!!))))'
print 'Enter the password: '
buf = raw_input()
if password == buf:
    print(flag)
else:
    print 'Wrong password!'
"""
#my code
def main():
    a = 'DCTF{09fa'
    c = '4d3142a6a'
    b = '7ab70e9aa'
    f = '1929d62e0'
    g = '805934d86'
    d = 'd4b55ea5b'
    e = '1a436b536'
    h = '59eadd}'
    flag = a + b + c + d + e + f + g + h
    print(flag)

if __name__ == "__main__":
    main()