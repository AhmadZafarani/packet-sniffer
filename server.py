# YA HOSSEIN
import socket


HOST = '127.0.0.1'
PORT = 8000


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(5)
    conn, addr = s.accept()

    print('Connected by', addr)
    while True:
        data = conn.recv(512)
        print(data.decode('ascii'))
        if not data:
            break
        conn.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
