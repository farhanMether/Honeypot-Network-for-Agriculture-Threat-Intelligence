import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client.connect(("localhost", 8888))
    
    data = client.recv(1024)
    print("Server Response:", data.decode())

except Exception as e:
    print("Error:", e)

finally:
    client.close()