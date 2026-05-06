import os

network = input("Enter network (e.g. 192.168.1): ")

for i in range(1, 255):
    ip = f"{network}.{i}"
    
    response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
    
    if response == 0:
        print(f"{ip} is active")
