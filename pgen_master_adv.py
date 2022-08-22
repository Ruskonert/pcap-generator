import socket
import sys
import os
import time
import signal
import subprocess

if os.geteuid() != 0:
    print("You need to sudo permission")
    sys.exit(1)

if len(sys.argv) < 4:
    print("Usuge: {} <host_ip> <start_port> <interface>".format(sys.argv[0]))
    sys.exit(0)

host = sys.argv[1]
port = int(sys.argv[2])

proc = None

protocol_name = input("What is protocol name? ")

print("Connecting server info: {}:{}".format(host, port))

name = "{}_port_{}_{}_{}.pcap".format(protocol_name, port, sys.argv[3], time.time_ns())
proc = subprocess.Popen(["tcpdump","-i","{}".format(sys.argv[3]),"host","{}".format(host), "and", "port", "{}".format(port), "-w", "{}".format(name)], shell=False)
time.sleep(0.4)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
print("Connected")

def handler(signum, frame):
    print("Control-C or terminate signal detected, exit...")
    if proc:
        os.kill(proc.pid, signal.SIGINT)
    print("Captured to: {}".format(name))

    if s:
        s.shutdown(socket.SHUT_RDWR)
        s.close()

    if s2:
        s2.shutdown(socket.SHUT_RDWR)
        s2.close()

    sys.exit(0)


signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)

time.sleep(1)

s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.connect((host, 44444))

print("Sync manager is connected, [{}:{}]".format(host, 44444))


while True:
    input_data = None
    ack_data = None
    wait_data = None

    while True:
        try:
            ack_data = bytes.fromhex(ack_data.upper())
        except ValueError:
            print("Please input the data properly! input data is should be odd length")
            continue

        if len(ack_data) != 0:
            s2.send(b"CONTINUE")
            s.send(ack_data)
        else:
            s2.send(b'END')
            break
    
    while True:
        wait_data = s2.recv(65535)
        if wait_data == b'CONTINUE':
            recv = s.recv(65535)
            print("Received data: len=[{}], d=[{}]".format(len(recv), recv.hex()))
        else:
            break