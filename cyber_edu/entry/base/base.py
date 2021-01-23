import struct
import socket
import time
###########
#     MY FIRST EVER CTF CHALLENGE

####READ FUNCTION, COULT BE BETTER
def read_and_print(s):
#socket as parameter
    time.sleep(0.3)
    message = s.recv(256)
    message = str(message)
    #print(message)
    return message

#EXTRACT THE THING INSIDE << >>
def extract_useful(mess):
    mess = mess.split("<<")[1]
    mess = mess.split(">>")[0]
    return mess
####CONNECTING
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    IP = '34.89.159.150'
    PORT = 30183
    s.connect((IP, PORT))
    ###############################################
    ####################TASK 1
    msg = read_and_print(s)
    msg = extract_useful(msg)
    #print(msg)

    msg = int(msg)
    msg = hex(msg)
    #print(msg)
    s.send(bytes(msg+'\n', 'utf-8'))

    ###############################################
    ####################TASK 2
    msg = read_and_print(s)
    msg = extract_useful(msg)
    #print(msg)

    bytes_object = bytes.fromhex(msg)
    ascii_string = bytes_object.decode("ASCII")
    #print(ascii_string)
    s.send(bytes(ascii_string+'\n', 'utf-8'))

    ###############################################
    ####################TASK 3
    msg = read_and_print(s)
    msg = extract_useful(msg)

    result = ''
    msg = msg.split()
    for i in msg:
        i = int(i, 8)
        result+=chr(i)
    #print(result)

    s.send(bytes(result+'\n', 'utf-8'))

    ######################################
    #########################GET THE FLAG
    msg = read_and_print(s)
    print(msg.strip("\\nb'"))

if __name__ == "__main__":
    main()