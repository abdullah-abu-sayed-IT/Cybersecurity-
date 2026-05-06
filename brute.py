import time

password = "1234"   # target password (demo)

guess_list = ["1111", "123", "0000", "9999", "1234"]

for guess in guess_list:
    print(f"Trying: {guess}")
    time.sleep(1)

    if guess == password:
        print("Password Found ✔️:", guess)
        break
