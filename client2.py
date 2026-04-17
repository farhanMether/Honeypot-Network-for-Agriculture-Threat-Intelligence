import socket
import time

for i in range(7):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(("localhost", 8888))
        data = client.recv(1024)
        print(f"Attempt {i+1}: {data.decode()}")
    except:
        print("Connection blocked")
    finally:
        client.close()
    
    time.sleep(1)