#!/usr/bin/python3

# Packet generator for L2, written by ruskonert
# Created Date: 2023. 01. 10

import socket
import getopt
import sys
import time
import subprocess
import signal
import os
import struct

PKT_EXEC_VERSION = '0.0.1'

print("Packet Generator for L2, Version {}".format(PKT_EXEC_VERSION))

def print_help():
    print("Usuge: {} [-h|--help] [-t|--time=<delay_interval_ms>] [-s|--source_mac=<MAC>] \
        [-d|--dest_mac=<MAC>] [-e|--etype=<hex>] [-l|--loop=<loop_count>] (rule_file)".format(sys.argv[0]))

PKT_IF_NAME         = None
PKT_TIME_DELAY      = 0
PKT_IS_SAVE         = True
PKT_FILE_PATH       = None
PKT_TCPDUMP_VERSION = None
PKT_SOURCE_MAC      = None
PKT_DEST_MAC        = None
PKT_ETYPE           = 0x0800 # it is default ethernet type (ipv4)
PKT_LOOP_COUNT      = 1


print()
for idx, arg_value in enumerate(sys.argv):
    print("ARGS[{}] = {}".format(idx, arg_value))
print()


if len(sys.argv) > 1:
    opts, args = getopt.getopt(sys.argv[1:], 'ht:s:d:e:l:', ['help', 'time=', 'source_mac=', 'dest_mac=', 'etype=', 'loop='])
    for option, arg in opts:
        if option in ['-t', '--time']:
            PKT_TIME_DELAY = int(arg)
        elif option in ['-l', '--loop']:
            PKT_LOOP_COUNT = int(arg)
        elif option in ['-h', '--help']:
            print_help()
            sys.exit(1)
        elif option in ['-s', '--source_mac']:
            PKT_SOURCE_MAC = arg
        elif option in ['-d', '--dest_mac']:
            PKT_DEST_MAC = arg
        elif option in ['-e', '--etype']:
            PKT_ETYPE = int(arg, base=16)
        else:
            continue
            
        
    if len(args) == 0:
        print("Please specify the rule file path!")
        sys.exit(0)
    
    PKT_FILE_PATH = args[0]
else:
    print_help()
    sys.exit(0)


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
print("Transport mode      : L2\n", end='')

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
        rule_type = 0 # no means
        str_payload = "".join(payload_arr[1:])
        raw_data = bytes.fromhex(str_payload)
        payload_amount += 1

        print("[{:4d}] LEN=[{:4d}], PAYLOAD=[{}]".format(payload_amount, len(raw_data), str_payload.upper()))

        PKT_PAYLOAD_DATA.append((rule_type, raw_data))

    except ValueError:
        print("[ERR] Error pasing when read data at line number {}".format(idx+1))
        sys.exit(1)

if PKT_IS_SAVE:
    print("*== Loading the tcpdump process  ...")

    filter_str = "ether proto 0x{:x}".format(PKT_ETYPE)

    # Generate subprocess
    argument = ['sudo', 'tcpdump', '-i', '{}'.format(PKT_IF_NAME), filter_str, '-w', '_pcap_temp_internal.pcap']
    # print("tcpdump command -> \"{}\"".format(' '.join(argument)))
    tcpdump_ps = subprocess.Popen(argument, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    # print("[INFO] tcpdump pid: {}".format((tcpdump_ps.pid)))
####################################################################################


print("*== Establish the socket  ...")
l2_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
time.sleep(0.5)


# Set the interface name and MAC addresses
interface_name = PKT_IF_NAME
src_mac_addr = b'\x00\x00\x00\x00\x00\x00'
dst_mac_addr = b'\x00\x00\x00\x00\x00\x00'

# Set the Ethernet header
eth_header = dst_mac_addr + src_mac_addr + struct.pack("!H", PKT_ETYPE)


for _ in range(PKT_LOOP_COUNT):
    for payload_idx in range(0, len(PKT_PAYLOAD_DATA)):
        payload = eth_header + PKT_PAYLOAD_DATA[payload_idx][1]
        l2_socket.sendto(payload, (PKT_IF_NAME, 0))
        if PKT_TIME_DELAY > 0:
            time.sleep(PKT_TIME_DELAY / 1000)

time.sleep(1)
print("*== Shutdown the payload send  ...")
l2_socket.close()

os.system("sudo pkill -2 -P " + str(tcpdump_ps.pid))

time.sleep(1)

if PKT_IS_SAVE:
    f = open("_pcap_temp_internal.pcap", 'rb')
    pcap_bin = f.read()
    f.close()

    pcap_bin = bytearray(pcap_bin)

    print("*== Change the PCAP info  ...")
    print("="*25)
    print("Spec Source MAC     : {}".format(PKT_SOURCE_MAC))
    print("Spec Destination MAC: {}".format(PKT_DEST_MAC))
    print("="*25)

    if PKT_SOURCE_MAC or PKT_DEST_MAC:
        bin_source_mac_data = None
        bin_dest_mac_data = None

        if PKT_SOURCE_MAC:
            bin_source_mac_data = bytes.fromhex("".join(PKT_SOURCE_MAC.split(":")))
            # print("[INFO] BIN_SOURCE_MAC_DATA: [{}]".format(bin_source_mac_data.hex()))
        
        if PKT_DEST_MAC:
            bin_dest_mac_data = bytes.fromhex("".join(PKT_DEST_MAC.split(":")))
            # print("[INFO] BIN_DEST_MAC_DATA: [{}]".format(bin_dest_mac_data.hex()))

        pos = 0
        eof_pos = len(pcap_bin)

        while True:
            if pos + 14 > eof_pos:
                break

            # check the ipv4 and mac is zero-filled
            if pcap_bin[pos:pos+12] == bytes.fromhex('00'* 12):
                if pcap_bin[pos+12:pos+14] == struct.pack("!H", PKT_ETYPE):
                    dest_mac_pos   = pos
                    source_mac_pos = pos+6
                    # next layer data
                    pos += 14
                    if bin_source_mac_data:
                        pcap_bin[source_mac_pos:source_mac_pos+6] = bin_source_mac_data
                    if bin_dest_mac_data:
                        pcap_bin[dest_mac_pos:dest_mac_pos+6] = bin_dest_mac_data
                else:
                    pos += 1
            else:
                pos += 1

            
    
    f = open(PKT_FILE_PATH.split(".")[0] + ".pcap", 'wb')
    f.write(pcap_bin)
    f.close()
    print("*== Save to PCAP  ... [{}]".format(PKT_FILE_PATH.split(".")[0] + ".pcap"))
    os.remove("_pcap_temp_internal.pcap")

print("*== Done!")
