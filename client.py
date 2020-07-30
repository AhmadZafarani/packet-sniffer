# YA ALI
import socket


HOST = '127.0.0.1'
PORT = 8000

message = b'GET /test.txt HTTP/1.1\r\n\r\n'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(message)
    data = s.recv(512)
    print(data.decode('ascii'))
