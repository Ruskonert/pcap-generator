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
print("Usuge server info: {}:{}".format(host, port))

s.bind((host, port))
s.listen()

client_socket, addr = s.accept()
print("Connected")

s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Usuge Sync server info: {}:{}".format(host, 44444))

s2.bind((host, 44444))
s2.listen()
client_sync_socket, addr = s2.accept()


def handler(signum, frame):
    print("Control-C detected, exit...")
    if client_socket:
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()

    if client_sync_socket:
        client_sync_socket.close()

    if s:
        s.close()

    if s2:
        s2.close()
    
    print("terminated!")
    sys.exit(0)


signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)

print("Sync manager is connected, [{}]".format(addr))
time.sleep(1)
while True:
    input_data = None
    ack_data = None
    wait_data = None

    while True:
        time.sleep(0.1)
        wait_data = client_sync_socket.recv(65535)
        if wait_data == b'CONTINUE':
            recv_data = client_socket.recv(65535)
            print("Received data: len=[{}], d=[{}]".format(len(recv_data), recv_data.hex()))
            continue
        else:
            break

    while True:
        ack_data = input("New Input data (if no data, turn end): ")

        try:
            ack_data = bytes.fromhex(ack_data.upper())
        except ValueError:
            print("Please input the data properly! input data is should be odd length")
            continue

        if len(ack_data) != 0:
            client_sync_socket.send(b"CONTINUE")
            client_socket.send(ack_data)
        else:
            client_sync_socket.send(b'END')
            break