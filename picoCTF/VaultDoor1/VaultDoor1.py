
def main():
    f = open("VaultDoor1.java", "r")
    arr = [''] * 40
    for x in f:
        if 'password.charAt' in x:
            number = x.strip().split('(')[1].split(')')[0]
            #print(number)
            car = x.strip().split("'")[1].split("'")[0]
            #print(car)
            arr[int(number)]=car
    sol=""
    for i in arr:
        sol+=i
    print("picoCTF{"+sol+"}")

if(__name__=="__main__"):
    main()
