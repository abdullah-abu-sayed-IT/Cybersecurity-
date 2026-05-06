import os
import threading

network = input("Enter network (e.g. 192.168.1): ")

def scan(ip):
    response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")
    if response == 0:
        print(f"[+] {ip} is active")

threads = []

for i in range(1, 255):
    ip = f"{network}.{i}"
    t = threading.Thread(target=scan, args=(ip,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()
