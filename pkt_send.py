#!/usr/bin/python3

# Packet generator, written by ruskonert
# Created Date: 2022. 11. 5

import socket
import getopt
import sys
import time
import subprocess
import signal
import threading
import os

from threading import Thread

PKT_EXEC_VERSION = '1.0.0'

print("Packet Generator {}".format(PKT_EXEC_VERSION))

def print_help():
    print("Usuge: {} [-h|--help] [-d|--delay=<interval_ms>] [-s|source_addr=<ip>:<port>] [-d|--dest_addr=<ip>:<port>] [--source_mac=<MAC>] [--dest_mac=<MAC>] [--tcp] [--udp] [--with-save] [rule_file]".format(sys.argv[0]))

PKT_IF_NAME         = None
PKT_TIME_DELAY      = 1000
PKT_SOURCE_IP       = "192.168.1.100"
PKT_SOURCE_PORT     = 2022
PKT_DEST_IP         = "192.168.1.10"
PKT_IS_SAVE         = False
PKT_DEST_PORT       = 2023
PKT_FILE_PATH       = None
PKT_TCPDUMP_VERSION = None
PKT_SOURCE_MAC      = None
PKT_DEST_MAC        = None
PKT_ENABLE_TCP      = False
PKT_ENABLE_UDP      = False

print()
for idx, arg_value in enumerate(sys.argv):
    print("ARGS[{}] = {}".format(idx, arg_value))
print()

if len(sys.argv) > 1:
    opts, args = getopt.getopt(sys.argv[1:], 'hs:d:t:', ['delay=', 'time=', 'source_addr=', 'dest_addr=', 'save', 'udp', 'tcp', 'source_mac=', 'dest_mac=', 'help'])
    for option, arg in opts:

        if option in ['-t', '--time']:
            PKT_TIME_DELAY = int(arg)

        elif option in ['-s', '--source_addr']:
            PKT_SOURCE_IP = arg

        elif option in ['-d', '--dest_addr']:
            PKT_DEST_IP = arg

        elif option in ['-h', '--help']:
            print_help()
            sys.exit(1)

        elif option in ['--save']:
            PKT_IS_SAVE = True

        elif option in ['--source_mac']:
            PKT_SOURCE_MAC = arg

        elif option in ['--dest_mac']:
            PKT_DEST_MAC = arg
        elif option in ['--delay']:
            PKT_TIME_DELAY = int(arg)
    
        elif option in ['--tcp']:
            if PKT_ENABLE_UDP:
                print("Please one select transport type (tcp or udp)!")
                sys.exit(1)
            PKT_ENABLE_TCP = True

        elif option in ['--udp']:
            if PKT_ENABLE_TCP:
                print("Please one select transport type (tcp or udp)!")
                sys.exit(1)
            PKT_ENABLE_UDP = True
        else:
            continue
            
        
    if len(args) == 0:
        print("Please specify the rule file path!")
        sys.exit(0)
    
    PKT_FILE_PATH = args[0]
else:
    print_help()
    sys.exit(0)


# check the ip address contains port number
if len(PKT_SOURCE_IP.split(":")) > 1:
    _sp = PKT_SOURCE_IP.split(":")
    PKT_SOURCE_IP = _sp[0]
    PKT_SOURCE_PORT = int(_sp[1])


if len(PKT_DEST_IP.split(":")) > 1:
    _sp = PKT_DEST_IP.split(":")
    PKT_DEST_IP = _sp[0]
    PKT_DEST_PORT = int(_sp[1])


## check the user has root permisssion
if os.getuid() != 0:
    print("You need to sudo permisssion")
    sys.exit(1)


## check the tcpdump is installed on the system
try:
    output = subprocess.check_output(["sudo", "tcpdump", "--version"]).decode('utf-8').replace("\n", ', ')[:-2]
    PKT_TCPDUMP_VERSION = output

except subprocess.CalledProcessError:
    print("Your system is not installed tcpdump. please install the tcpdump!")
    sys.exit(1)



## check the network interface
for idx, if_name in socket.if_nameindex():
    if if_name.find('lo') != -1:
        PKT_IF_NAME = if_name
        break

if PKT_IF_NAME is None:
    print("Oops, we need to loopback interface but this system is not configured network interface!")
    sys.exit(1)

print("="*25)
print("Your settings are:")
print("Source IP           : {}:{}".format(PKT_SOURCE_IP, PKT_SOURCE_PORT))
print("Destination IP      : {}:{}".format(PKT_DEST_IP, PKT_DEST_PORT))
print("Interval Time Delay : {} ms".format(PKT_TIME_DELAY))
print("Rule time path      : {}".format(PKT_FILE_PATH))

enable_str = 'Disabled'
if PKT_IS_SAVE:
    enable_str = 'Enabled'
print("PCAP saved          : {}".format(enable_str))
print("="*25)
print()
print("="*25)
print("Your system config:")
print("Usuge for captured : {}".format(PKT_IF_NAME))
print("tcpdump info       : {}".format(PKT_TCPDUMP_VERSION))
print("="*25)
print()

print("*== Loading the rule data ...")

f = open('test.txt')
bin_data = f.read()

PKT_PAYLOAD_DATA = []

payload_amount = 0

PRINT_DIRECTION_STR = ['SRC->DST', 'DST->SRC']

for idx, payload in enumerate(bin_data.split('\n')):
    if len(payload) == 0:
        continue

    if payload[0] == '#':
        continue

    payload_arr = payload.split(" ")

    if len(payload_arr) < 2:
        print("[ERR] Payload is missing, Error pasing when read data at line number {}".format(idx+1))
        sys.exit(1)

    try:
        rule_type = int(payload_arr[0])
        str_payload = "".join(payload_arr[1:])
        raw_data = bytes.fromhex(str_payload)

        payload_amount += 1

        print("[{}] PKT: DIR=[{}], LEN=[{}], PAYLOAD=[{}]".format(payload_amount, PRINT_DIRECTION_STR[rule_type], len(raw_data), str_payload.upper()))

        PKT_PAYLOAD_DATA.append((rule_type, raw_data))

    except ValueError:
        print("[ERR] Error pasing when read data at line number {}".format(idx+1))
        sys.exit(1)

if PKT_IS_SAVE:
    print("*== Loading the tcpdump process  ...")

    filter_str = None

    if PKT_ENABLE_TCP:
        filter_str = 'tcp port {}'.format(PKT_DEST_PORT)
    else:
        filter_str = 'udp port {}'.format(PKT_DEST_PORT)

    # Generate subprocess
    argument = ['sudo', 'tcpdump', '-i', '{}'.format(PKT_IF_NAME), '-w', '{}.pcap'.format(PKT_FILE_PATH), filter_str]
    print("tcpdump command -> \"{}\"".format(' '.join(argument)))
    tcpdump_ps = subprocess.Popen(argument, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    print("[INFO] tcpdump pid: {}".format((tcpdump_ps.pid)))

print("*== Establishing the socket  ...")

# Establishing socket process
slave_s = None
master_s = None

if PKT_ENABLE_TCP:
    master_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    master_s.bind(('localhost', PKT_DEST_PORT))
    master_s.listen(1)
else:
    master_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    master_s.bind(('localhost', PKT_DEST_PORT))



def _start_slave_func():
    global slave_s

    time.sleep(1)
    if PKT_ENABLE_TCP:
        slave_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        slave_s.bind(('0.0.0.0', PKT_SOURCE_PORT))
        slave_s.connect(('localhost', PKT_DEST_PORT))
        print("[INFO] Connected Slave->Master")
    else:
        slave_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        slave_s.bind(('0.0.0.0', PKT_SOURCE_PORT))
        print("[INFO] Generated Socket: Slave->Master [UDP]")




th1 = Thread(target=_start_slave_func, args=())
th1.start()

if PKT_ENABLE_TCP:
    conn_slave_s, addr = master_s.accept()

print("[INFO] Connected Master->Slave")
th1.join()

socket_lock = threading.Lock()


def _send_packet_data_tcp(s1, s2, direction, payload_data):
    socket_lock.acquire()
    if direction == 0:
        print('Slave SEND: [{}]'.format(payload_data.hex()))
        s1.send(payload_data)
        time.sleep(0.05)
        print('Master RECV: [{}]'.format(s2.recv(65535).hex()))
    elif direction == 1:
        print('Master SEND: [{}]'.format(payload_data.hex()))
        s2.send(payload_data)
        time.sleep(0.05)
        print('Slave RECV: [{}]'.format(s1.recv(65535).hex()))
    else:
        print("Unknown")
    socket_lock.release()


def _send_packet_data_udp(s1, s2, slave_addr, master_addr, direction, payload_data):
    socket_lock.acquire()
    if direction == 0:
        print('Slave SEND : [{}]'.format(payload_data.hex()))
        s1.sendto(payload_data, master_addr)
        time.sleep(0.05)
        print('Master RECV: [{}]'.format(s2.recvfrom(65535)[0].hex()))
    elif direction == 1:
        print('Master SEND: [{}]'.format(payload_data.hex()))
        s2.sendto(payload_data, slave_addr)
        time.sleep(0.05)
        print('Slave RECV : [{}]'.format(s1.recvfrom(65535)[0].hex()))
    else:
        print("Unknown")
    socket_lock.release()

time.sleep(1)

print("*== Start the payload send  ...")

for payload_idx in range(0, len(PKT_PAYLOAD_DATA)):
    if PKT_ENABLE_TCP:
        _send_packet_data_tcp(slave_s, conn_slave_s, PKT_PAYLOAD_DATA[payload_idx][0], PKT_PAYLOAD_DATA[payload_idx][1])
    else:
        _send_packet_data_udp(slave_s, master_s, ('localhost', PKT_SOURCE_PORT), ('localhost', PKT_DEST_PORT), PKT_PAYLOAD_DATA[payload_idx][0], PKT_PAYLOAD_DATA[payload_idx][1])
    
    socket_lock.acquire()
    time.sleep(PKT_TIME_DELAY / 1000)
    socket_lock.release()

print("*== Shutdown the payload send  ...")

if PKT_ENABLE_TCP:
    slave_s.shutdown(socket.SHUT_RDWR)
    time.sleep(0.5)

slave_s.close()
master_s.close()

time.sleep(0.5)

if PKT_IS_SAVE:
    print("*== Save to PCAP  ...")
    os.kill(tcpdump_ps.pid, signal.SIGTERM)


print("*== Done!")
