import socket
from datetime import datetime

HOST = "0.0.0.0"
PORT = 9999
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"Listening UDP on {HOST}:{PORT}")

while True:
    data, addr = sock.recvfrom(65535)
    now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{now}] from {addr[0]}:{addr[1]} len={len(data)} preview={data[:80]!r}")

