#!/usr/bin/python3

# Packet generator for L2, written by ruskonert
# Created Date: 2023. 02. 15

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
    print("Usuge: {} [-h|--help] [-t|--time=<delay_interval_ms>] [-e|--etype=<hex>] [-o|--output=<PCAP_NAME>] [-l|--loop=<loop_count>] (rule_file)".format(sys.argv[0]))

PKT_IF_NAME         = None
PKT_TIME_DELAY      = 0
PKT_IS_SAVE         = True
PKT_FILE_PATH       = None
PKT_OUTPUT_NAME     = "output"
PKT_TCPDUMP_VERSION = None
PKT_ETYPE           = 0x0800 # it is default ethernet type (ipv4)
PKT_LOOP_COUNT      = 1


print()
for idx, arg_value in enumerate(sys.argv):
    print("ARGS[{}] = {}".format(idx, arg_value))
print()


if len(sys.argv) > 1:
    opts, args = getopt.getopt(sys.argv[1:], 'ht:e:l:o:', ['help', 'output=', 'time=', 'etype=', 'loop='])
    for option, arg in opts:
        if option in ['-t', '--time']:
            PKT_TIME_DELAY = int(arg)
        elif option in ['-l', '--loop']:
            PKT_LOOP_COUNT = int(arg)
        elif option in ['-h', '--help']:
            print_help()
            sys.exit(1)
        elif option in ['-o', '--output']:
            PKT_OUTPUT_NAME = arg.replace(".pcap", "")
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


variables = {}

####################################################################################
# load the rule
for idx, payload in enumerate(bin_data.split('\n')):
    if len(payload) == 0:
        continue

    if payload[0] == '#':
        continue

    if "=" in payload:
        var_value = payload.split('=')
        if len(var_value) < 2:
            print("[ERR] Unexpected declearing the variable at line number {}".format(idx+1))
            sys.exit(2)
        var_name = var_value[0].replace(" ", '')
        mac = bytes.fromhex(var_value[1].replace(" ", '').replace(":", ""))
        if len(mac) != 6:
            print("[ERR] invaild mac type at line number {}".format(idx+1))
            sys.exit(2)
        variables[var_name] = mac
        print("==* set variable: [{}]=>[{}]".format(var_name, mac.hex()))
        continue

    payload_arr = payload.split(" ")

    if len(payload_arr) < 2 or len(payload_arr[1]) == 0:
        print("[ERR] Payload is missing, Error pasing when read data at line number {}".format(idx+1))
        sys.exit(1)

    try:
        src_mac = payload_arr[0]
        dst_mac = payload_arr[1]
        if src_mac in variables:
            src_mac = variables[src_mac]
        else:
            src_mac = bytes.fromhex(src_mac.replace(":", ''))

        if dst_mac in variables:
            dst_mac = variables[dst_mac]
        else:
            dst_mac = bytes.fromhex(dst_mac.replace(":", ''))

        payload = bytes.fromhex("".join(payload_arr[2:]))
        payload_amount += 1

        print("[{:4d}] => LEN={:03d}, SRC=[{}], dst=[{}], payload=[{}]".format(payload_amount, len(payload), src_mac.hex().upper(), dst_mac.hex().upper(), payload.hex().upper()))
        PKT_PAYLOAD_DATA.append([src_mac, dst_mac, payload])

    except:
        print("[ERR] Error pasing when read data at line number {}".format(idx+1))
        sys.exit(1)

if PKT_IS_SAVE:
    print("*== Loading the tcpdump process  ...")
    filter_str = "ether proto 0x{:x}".format(PKT_ETYPE)

    # Generate subprocess
    argument = ['sudo', 'tcpdump', '-i', '{}'.format(PKT_IF_NAME), filter_str,  '-w', '_pcap_temp_internal.pcap']
    print("tcpdump command -> \"{}\"".format(' '.join(argument)))
    tcpdump_ps = subprocess.Popen(argument, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    print("[INFO] tcpdump pid: {}".format((tcpdump_ps.pid)))
####################################################################################


print("*== Establish the socket  ...")
l2_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
time.sleep(0.5)


for _ in range(PKT_LOOP_COUNT):
    for payload_col in PKT_PAYLOAD_DATA:
        eth_header = payload_col[1] + payload_col[0]  + struct.pack("!H", PKT_ETYPE)
        l2_socket.sendto(eth_header + payload_col[2], (PKT_IF_NAME, 0))
        if PKT_TIME_DELAY > 0:
            time.sleep(PKT_TIME_DELAY / 1000)
    
time.sleep(1)
print("*== Shutdown the payload send  ...")
l2_socket.close()
os.system("sudo pkill -2 -P " + str(tcpdump_ps.pid))

time.sleep(2)

if PKT_IS_SAVE:
    f = open("_pcap_temp_internal.pcap", 'rb')
    pcap_bin = f.read()
    f.close()

    f = open("{}.pcap".format(PKT_OUTPUT_NAME), 'wb')
    f.write(pcap_bin)
    f.close()
    print("*== Save to PCAP  ... [{}]".format(PKT_OUTPUT_NAME + ".pcap"))
    os.remove("_pcap_temp_internal.pcap")

print("*== Done!")
