import hashlib


#simple 
def crackpass(input_hash,wordlist):
    with open(wordlist,'r') as file : 
        for word in file : 
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == input_hash:
                print(f"password found: {word}")
                return 
    print("Password not found")

input_hash=input("Enter hash to crack: ")
wordlist = "wordlists.txt"
crackpass(input_hash,wordlist)

#update on this code from below
