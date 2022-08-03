import socket
import sys
import signal
import subprocess
import os
import time

if len(sys.argv) < 3:
    print("Usuge: {} <port> <interface>".format(sys.argv[0]))
    sys.exit(0)

host = '0.0.0.0'
port = int(sys.argv[1])

print("Usuge interface: {}".format(sys.argv[2]))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, 25, "{}".format(sys.argv[2]).encode())
print("Usuge server info: {}:{}".format(host, port))

s.bind((host, port))
s.listen()

client_socket, addr = s.accept()
print("Connected")

def handler(signum, frame):
    print("Control-C detected, exit...")
    if client_socket:
        client_socket.close()

    if s:
        s.close()
    print("terminated!")
    sys.exit(0)



signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)


while True:
    count = 0
    input_data = None
    while True:
        data = client_socket.recv(65535)
        print("Received, data length=[{}]".format(len(data)))

        if not input_data:
            while True:
                try:
                    input_data = input("recv data: ")
                    bytes.fromhex(input_data.upper())
                    break
                except ValueError:
                    print("Please input data again! invaild data")


        client_socket.send(bytes.fromhex(input_data.upper()))
        time.sleep(0.4)

        if count == 2:
            break
        else:
            count = count + 1

    print("Completed capture job, next function")