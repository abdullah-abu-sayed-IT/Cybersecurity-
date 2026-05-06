import time

# target password (demo only)
password = "admin123"

# wordlist (possible passwords)
wordlist = [
    "1234",
    "password",
    "admin",
    "admin123",
    "letmein",
    "qwerty"
]

print("Starting brute force attack simulation...\n")

for guess in wordlist:
    print(f"Trying: {guess}")
    time.sleep(0.5)

    if guess == password:
        print("\n✔ Password Found:", guess)
        break

else:
    print("\n❌ Password not found in wordlist")
