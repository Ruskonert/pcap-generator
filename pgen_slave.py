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
s.setsockopt(socket.SOL_SOCKET, 25, '{}'.format(sys.argv[3]).encode())
s.connect((host, port))
print("Connected")

def handler(signum, frame):
    print("Control-C detected, exit...")
    if proc:
        os.kill(proc.pid, signal.SIGINT)
    print("Captured to: {}".format(name))

    if s:
        s.close()
    sys.exit(0)


signal.signal(signal.SIGINT, handler)
signal.signal(signal.SIGTERM, handler)

while True:    
    count = 0

    while True:
        try:
            input_data = input("New Input data: ")
            bytes.fromhex(input_data.upper())
            break
        except ValueError:
            print("Please input data again! invaild data")

    if len(input_data) <= 0:
        continue

    elif len(input_data) % 2 != 0:
        print("Please input the raw data and must have even length")
        continue

    while True:
        s.send(bytes.fromhex(input_data.upper()))
        time.sleep(0.4)
        aa = s.recv(65535)
        print("recv: {}".format(aa))
        if count == 2:
            break
        else:
            count = count + 1
    
    print("Completed capture job, next function")
    time.sleep(1)
