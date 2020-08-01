# YA ALI
import socket


HOST = '127.0.0.1'
PORT = 8000
message = b'POST /test HTTP/1.1\r\nHost: foo.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nfield1=value1&field2=value2\r\n\r\n'
# message = b'GET / HTTP/1.1\r\n\r\n'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(message)
    data = s.recv(1024)
    print(data.decode('ascii'))
