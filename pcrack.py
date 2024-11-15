import hashlib

HASH_FUNCTIONS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
}

def crack_hash(input_hash, wordlist, hash_type=None):
    try:
        with open(wordlist, 'r') as file:
            words = file.readlines()
            total_words = len(words)
            print(f"Total words in the wordlist: {total_words}")
            for count, word in enumerate(words, start=1):
                word = word.strip()
                print(f"Checking {count}/{total_words}: {word}")
                if hash_type:
                    if HASH_FUNCTIONS[hash_type](word.encode()).hexdigest() == input_hash:
                        print(f"Password found: {word} (hashed using {hash_type})")
                        return
                else:
                    for name, func in HASH_FUNCTIONS.items():
                        if func(word.encode()).hexdigest() == input_hash:
                            print(f"Password found: {word} (hashed using {name})")
                            return
        print("Password not found or unsupported hash type.")
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist}' not found.")
    except KeyboardInterrupt:
        print("\nExited through keyboard interruption.")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    try:
        while True:
            input_hash = input("Enter hash to crack: ").strip()
            wordlist = input("Enter wordlist file name (e.g., example.txt): ").strip()
            print("1. Check using all hash types")
            for i, name in enumerate(HASH_FUNCTIONS.keys(), start=2):
                print(f"{i}. {name}")
            choice = input("Select an option: ").strip()
            if choice == "1":
                crack_hash(input_hash, wordlist)
            elif choice.isdigit() and int(choice) in range(2, len(HASH_FUNCTIONS) + 2):
                hash_type = list(HASH_FUNCTIONS.keys())[int(choice) - 2]
                crack_hash(input_hash, wordlist, hash_type)
            else:
                print("Invalid choice. Please try again.")
    except KeyboardInterrupt:
        print("\nExited through keyboard interruption.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
