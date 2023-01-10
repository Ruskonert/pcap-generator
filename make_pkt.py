#!/usr/bin/python3

# Packet generator, written by ruskonert
# Created Date: 2022. 11. 7
#
# Updated issues:
#
# 2023. 01. 10: desc error fixed
#

import socket
import getopt
import sys
import time
import subprocess
import signal
import threading
import os
import ctypes
import struct

from threading import Thread

PKT_EXEC_VERSION = '1.0.0'

print("Packet Generator {}".format(PKT_EXEC_VERSION))

def print_help():
    print("Usuge: {} [-h|--help] [-t|--time=<delay_interval_ms>] [-s|--source_addr=<ip>:<port>] [-d|--dest_addr=<ip>:<port>] [--source_mac=<MAC>] [-l|--loop=<loop_count>] [--dest_mac=<MAC>] [--tcp] [--udp] (rule_file)".format(sys.argv[0]))

PKT_IF_NAME         = None
PKT_TIME_DELAY      = 0
PKT_SOURCE_IP       = None
PKT_SOURCE_PORT     = 12345
PKT_DEST_IP         = None
PKT_IS_SAVE         = True
PKT_DEST_PORT       = 4523
PKT_FILE_PATH       = None
PKT_TCPDUMP_VERSION = None
PKT_SOURCE_MAC      = None
PKT_DEST_MAC        = None
PKT_LOOP_COUNT      = 1
PKT_ENABLE_TCP      = False
PKT_ENABLE_UDP      = False

print()
for idx, arg_value in enumerate(sys.argv):
    print("ARGS[{}] = {}".format(idx, arg_value))
print()

if len(sys.argv) > 1:
    opts, args = getopt.getopt(sys.argv[1:], 'hs:d:t:l:', ['time=', 'source_addr=', 'loop=', 'dest_addr=', 'save', 'udp', 'tcp', 'source_mac=', 'dest_mac=', 'help'])
    for option, arg in opts:

        if option in ['-t', '--time']:
            PKT_TIME_DELAY = int(arg)

        elif option in ['-s', '--source_addr']:
            PKT_SOURCE_IP = arg

        elif option in ['-d', '--dest_addr']:
            PKT_DEST_IP = arg

        elif option in ['l', '--loop']:
            PKT_LOOP_COUNT = int(arg)

        elif option in ['-h', '--help']:
            print_help()
            sys.exit(1)

        elif option in ['--source_mac']:
            PKT_SOURCE_MAC = arg

        elif option in ['--dest_mac']:
            PKT_DEST_MAC = arg
    
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

if not PKT_ENABLE_TCP and not PKT_ENABLE_UDP:
    print("[INFO] transport type not specified, Use TCP mode")
    PKT_ENABLE_TCP = True


# check the ip address contains port number
if PKT_SOURCE_IP and len(PKT_SOURCE_IP.split(":")) > 1:
    _sp = PKT_SOURCE_IP.split(":")
    PKT_SOURCE_IP = _sp[0]
    PKT_SOURCE_PORT = int(_sp[1])


if PKT_DEST_IP and len(PKT_DEST_IP.split(":")) > 1:
    _sp = PKT_DEST_IP.split(":")
    PKT_DEST_IP = _sp[0]
    PKT_DEST_PORT = int(_sp[1])

IS_WINDOWS = False

## check the user has root permisssion
try:
    if os.getuid() != 0:
        print("You need to sudo permisssion")
        sys.exit(1)
except AttributeError:
    IS_WINDOWS = True
    print("Not yet supported the Windows OS, Sorry!")
    sys.exit(1)
    


## check the tcpdump is installed on the system
try:
    _proc = subprocess.Popen(['sudo', 'tcpdump', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = _proc.communicate()
    if output[0]:
        PKT_TCPDUMP_VERSION = output[0].decode('utf-8').replace('\n', ', ')[:-2]
    else:
        PKT_TCPDUMP_VERSION = output[1].decode('utf-8').replace('\n', ', ')[:-2]

except subprocess.CalledProcessError:
    print("Your system is not installed tcpdump. please install tcpdump!")
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
print("Interval time delay : {} ms".format(PKT_TIME_DELAY))
print("Rule time path      : {}".format(PKT_FILE_PATH))
print("Loop count          : {}".format(PKT_LOOP_COUNT))
print("Transport mode      : ", end='')
if PKT_ENABLE_TCP:
    print("TCP")
else:
    print("UDP")

enable_str = 'Disabled'
if PKT_IS_SAVE:
    enable_str = 'Enabled'

print("PCAP saved          : {}".format(enable_str))
print("Usuge for captured  : {}".format(PKT_IF_NAME))
print("tcpdump info        : {}".format(PKT_TCPDUMP_VERSION))
print("="*25)
print()

print("*== Loading the rule data ...")

f = open(PKT_FILE_PATH)
bin_data = f.read()
f.close()

PKT_PAYLOAD_DATA = []

payload_amount = 0
tcpdump_ps = None

slave_s = None
master_s = None
th1 = None

def interrupt_exit(s, _):
    print("*== Interrupt call ... {}".format(s))
    if th1:
        th1.join()
    
    if tcpdump_ps:
        os.system("sudo pkill -2 -P " + str(tcpdump_ps.pid))
        os.remove("_pcap_temp_internal.pcap")
    
    try:
        if slave_s:
            slave_s.close()
        
        if master_s:
            master_s.close()
    except:
        pass


signal.signal(signal.SIGTERM, interrupt_exit)
signal.signal(signal.SIGABRT, interrupt_exit)
signal.signal(signal.SIGINT, interrupt_exit)



####################################################################################
# load the rule
PRINT_DIRECTION_STR = ['SRC->DST', 'DST->SRC']

for idx, payload in enumerate(bin_data.split('\n')):
    if len(payload) == 0:
        continue

    if payload[0] == '#':
        continue

    payload_arr = payload.split(" ")

    if len(payload_arr) < 2 or len(payload_arr[1]) == 0:
        print("[ERR] Payload is missing, Error pasing when read data at line number {}".format(idx+1))
        sys.exit(1)

    try:
        rule_type = int(payload_arr[0])
        str_payload = "".join(payload_arr[1:])
        # raw_data = str_payload.encode()
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
        filter_str = 'tcp port {} or tcp port {}'.format(PKT_DEST_PORT, PKT_SOURCE_PORT)
    else:
        filter_str = 'udp port {} or udp port {}'.format(PKT_DEST_PORT, PKT_SOURCE_PORT)

    # Generate subprocess
    argument = ['sudo', 'tcpdump', '-i', '{}'.format(PKT_IF_NAME), filter_str, '-w', '_pcap_temp_internal.pcap']
    # print("tcpdump command -> \"{}\"".format(' '.join(argument)))
    tcpdump_ps = subprocess.Popen(argument, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    # print("[INFO] tcpdump pid: {}".format((tcpdump_ps.pid)))
####################################################################################



####################################################################################
# Establishing socket process
print("*== Establish the socket  ...")

if PKT_ENABLE_TCP:
    master_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    master_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    master_s.bind(('localhost', PKT_DEST_PORT))
    master_s.listen(1)
else:
    master_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    master_s.bind(('localhost', PKT_DEST_PORT))

def _start_slave_func():
    global slave_s

    time.sleep(0.5)
    if PKT_ENABLE_TCP:
        slave_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        slave_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        slave_s.bind(('0.0.0.0', PKT_SOURCE_PORT))
        slave_s.connect(('localhost', PKT_DEST_PORT))
        # print("[INFO] Connected Slave->Master")
    else:
        slave_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        slave_s.bind(('0.0.0.0', PKT_SOURCE_PORT))
        # print("[INFO] Generated Socket: Slave->Master [UDP]")


th1 = Thread(target=_start_slave_func, args=())
th1.start()

if PKT_ENABLE_TCP:
    conn_slave_s, addr = master_s.accept()
th1.join()


####################################################################################

socket_lock = threading.Lock()

def _send_packet_data_tcp(s1, s2, direction, payload_data):
    socket_lock.acquire()
    if direction == 0:
        # print('Slave SEND: [{}]'.format(payload_data.hex()))
        s1.send(payload_data)
        s2.recv(65535)
    elif direction == 1:
        # print('Master SEND: [{}]'.format(payload_data.hex()))
        s2.send(payload_data)
        s1.recv(65535)
    else:
        pass
        #print("Unknown")
    socket_lock.release()

def _send_packet_data_udp(s1, s2, slave_addr, master_addr, direction, payload_data):
    socket_lock.acquire()
    if direction == 0:
        s1.sendto(payload_data, master_addr)
        s2.recvfrom(65535)
    elif direction == 1:
        s2.sendto(payload_data, slave_addr)
        s1.recvfrom(65535)
    else:
        pass
        #print("Unknown")
    socket_lock.release()

print("*== Start the generating payload  ...")

for _ in range(PKT_LOOP_COUNT):
    for payload_idx in range(0, len(PKT_PAYLOAD_DATA)):
        # print("[Info] Executed {}'s payload data".format(payload_idx))
        if PKT_ENABLE_TCP:
            _send_packet_data_tcp(slave_s, conn_slave_s, PKT_PAYLOAD_DATA[payload_idx][0], PKT_PAYLOAD_DATA[payload_idx][1])
        else:
            _send_packet_data_udp(slave_s, master_s, ('localhost', PKT_SOURCE_PORT), ('localhost', PKT_DEST_PORT), PKT_PAYLOAD_DATA[payload_idx][0], PKT_PAYLOAD_DATA[payload_idx][1])
        
        socket_lock.acquire()
        
        if PKT_TIME_DELAY > 0:
            time.sleep(PKT_TIME_DELAY / 1000)
        socket_lock.release()

time.sleep(1)

print("*== Shutdown the payload send  ...")

if PKT_ENABLE_TCP:
    slave_s.shutdown(socket.SHUT_RDWR)
    conn_slave_s.shutdown(socket.SHUT_RDWR)
    conn_slave_s.close()

slave_s.close()
master_s.close()

os.system("sudo pkill -2 -P " + str(tcpdump_ps.pid))

time.sleep(1)

if PKT_IS_SAVE:
    f = open("_pcap_temp_internal.pcap", 'rb')
    pcap_bin = f.read()
    f.close()

    pcap_bin = bytearray(pcap_bin)

    print("*== Change the PCAP info  ...")
    print("="*25)
    print("Spec Source IP      : {}:{}".format(PKT_SOURCE_IP, PKT_SOURCE_PORT))
    print("Spec Destination IP : {}:{}".format(PKT_DEST_IP, PKT_DEST_PORT))
    print("Spec Source MAC     : {}".format(PKT_SOURCE_MAC))
    print("Spec Destination MAC: {}".format(PKT_DEST_MAC))
    print("="*25)

    if PKT_SOURCE_IP or PKT_DEST_IP or PKT_SOURCE_MAC or PKT_DEST_MAC:
        bin_source_mac_data = None
        bin_dest_mac_data = None
        bin_source_ip_data = None
        bin_dest_ip_data = None

        if PKT_SOURCE_MAC:
            bin_source_mac_data = bytes.fromhex("".join(PKT_SOURCE_MAC.split(":")))
            # print("[INFO] BIN_SOURCE_MAC_DATA: [{}]".format(bin_source_mac_data.hex()))
        
        if PKT_DEST_MAC:
            bin_dest_mac_data = bytes.fromhex("".join(PKT_DEST_MAC.split(":")))
            # print("[INFO] BIN_DEST_MAC_DATA: [{}]".format(bin_dest_mac_data.hex()))

        if PKT_SOURCE_IP:
            ip_str = ''
            for ip_attr in PKT_SOURCE_IP.split("."):
                ip_str += "{:02x}".format(int(ip_attr))
            bin_source_ip_data = bytes.fromhex(ip_str)
            # print("[INFO] BIN_SOURCE_IP DATA: [{}]".format(bin_source_ip_data.hex()))

        if PKT_DEST_IP:
            ip_str = ''
            for ip_attr in PKT_DEST_IP.split("."):
                ip_str += "{:02x}".format(int(ip_attr))
            bin_dest_ip_data = bytes.fromhex(ip_str)
            # print("[INFO] BIN_DEST_IP DATA: [{}]".format(bin_source_ip_data.hex()))

        pos = 0
        eof_pos = len(pcap_bin)

        while True:
            if pos + 14 > eof_pos:
                break

            # check the ipv4 and mac is zero-filled
            if pcap_bin[pos:pos+14] == bytes.fromhex('0000000000000000000000000800'):
                dest_mac_pos   = pos
                source_mac_pos = pos+6
                
                # next ip layer data
                pos += 14

                # next to ip field
                pos += 12

                source_ip_pos = pos
                dest_ip_pos   = pos+4

                # next to tcp/udp field
                pos += 8

                source_port = struct.unpack(">H", pcap_bin[pos:pos+2])[0]
                dest_port = struct.unpack(">H", pcap_bin[pos+2:pos+4])[0]

                is_reverse = True
                if source_port == PKT_SOURCE_PORT:
                    is_reverse = False

                if is_reverse:
                    if bin_source_mac_data:
                        pcap_bin[dest_mac_pos:dest_mac_pos+6] = bin_source_mac_data
                    if bin_dest_mac_data:
                        pcap_bin[source_mac_pos:source_mac_pos+6] = bin_dest_mac_data
                    if bin_source_ip_data:
                        pcap_bin[dest_ip_pos:dest_ip_pos+4] = bin_source_ip_data
                    if bin_dest_ip_data:
                        pcap_bin[source_ip_pos:source_ip_pos+4] = bin_dest_ip_data
                else:
                    if bin_source_mac_data:
                        pcap_bin[source_mac_pos:source_mac_pos+6] = bin_source_mac_data
                    if bin_dest_mac_data:
                        pcap_bin[dest_mac_pos:dest_mac_pos+6] = bin_dest_mac_data
                    if bin_source_ip_data:
                        pcap_bin[source_ip_pos:source_ip_pos+4] = bin_source_ip_data
                    if bin_dest_ip_data:
                        pcap_bin[dest_ip_pos:dest_ip_pos+4] = bin_dest_ip_data
                pos += 32
            else:
                pos += 1

            
    
    f = open(PKT_FILE_PATH.split(".")[0] + ".pcap", 'wb')
    f.write(pcap_bin)
    f.close()
    print("*== Save to PCAP  ... [{}]".format(PKT_FILE_PATH.split(".")[0] + ".pcap"))
    os.remove("_pcap_temp_internal.pcap")

print("*== Done!")
