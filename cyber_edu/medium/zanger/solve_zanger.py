#!/usr/bin/python3
import os

def main():
    os.system("tshark -r flag.pcap -Y 'tcp' -T text -e 'tcp.dstport' -Tfields > ports")
    text = open("ports", 'r').read().split('\n')[:-1]
    # split by newlines are remote the last char since it is empty
    flag = ''
    for i in range(0, len(text), 2):
        if text[i+1] == '1337':
            if i == len(text)-2:
                flag += '}'
            else: flag += '{'
        else:
            flag += bytes.fromhex(text[i] + text[i+1]).decode()
    os.system("rm ports")
    print(flag)

if __name__ == "__main__":
    main()