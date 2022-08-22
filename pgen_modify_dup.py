import sys 
import os

def isprintable(s):
    if not chr(s) in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~':
        return False
    return True

def get_mac_addr_bin(input_data):
    mac = None
    if ':' in input_data:
        mac = bytes.fromhex(''.join(input_data.split(":")))
    else:
        mac = bytes.fromhex(input_data)
    return bytearray(mac)


def get_ip_addr_bin(input_data):
    ip = None
    if '.' in input_data:
        ip = input_data.split(".")
    else:
        raise ValueError("Not IP format!")
    return bytearray([int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3])])


if len(sys.argv) < 2:
    print("usuge: {} [pcap_path]".format(sys.argv[0]))
    sys.exit(0)


f = open(sys.argv[1], 'rb')
data = bytearray(f.read())

f.close()

for i in range(0, len(data)):

    print('{:02x} '.format(data[i]), end='')
    if i + 1 == len(data) or (i % 16 == 0 and i != 0):
        print("   ", end='')
        for j in range(15, -1, -1):
            v = data[i-j]
            if isprintable(v):
                print("{}".format(chr(v)), end='')
            else:
                print(".", end='')
        print()
    if i % 16 == 0:
        print("{:016x}:  ".format(i), end='')

print()
print()
print("PCAP INFO: {}, size: {} byte(s)".format(sys.argv[1], len(data)))

scada_old_mac = get_mac_addr_bin(input("Input the SCADA Mac (Default - 00:18:7d:ff:77:3a): "))

if len(scada_old_mac) == 0:
    scada_old_mac = get_mac_addr_bin('00:18:7d:ff:77:3a')

slave_old_mac = get_mac_addr_bin(input("Input the SLAVE Mac: "))

pos = 0

scada_ip = None
slave_ip = None

# find the ip info
while True:
    if pos + 34 >= len(data):
        break

    src_mac = data[pos:pos+6]
    dst_mac = data[pos+6:pos+12]

    if src_mac == slave_old_mac and dst_mac == scada_old_mac:
        if data[pos+12:pos+14] != bytes.fromhex("0800"):
            pos += 1
            continue

        scada_ip = data[pos+26:pos+30]
        slave_ip = data[pos+30:pos+34]
        break
    pos += 1

print()
print("=======================================")
print("          MAC/ADDRESS INFO\n")
print("SCADA IP:  {:d}.{:d}.{:d}.{:d}".format(*tuple(scada_ip)))
print("SCADA MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*tuple(scada_old_mac)))
print()
print("SLAVE IP:  {:d}.{:d}.{:d}.{:d}".format(*tuple(slave_ip)))
print("SLAVE MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*tuple(slave_old_mac)))
print("\n=======================================")
print()

if not scada_ip or not slave_ip:
    print("Not found SRC ip or DST ip... is it normal PCAP file (PCAP file contains L4-layer data)?")
    print("Please check the PCAP file")
    sys.exit(0)



def calc_ip_increase(target_ip, how_increase):
    new_ip = bytearray(target_ip)

    if len(new_ip) != 4:
        raise ValueError("IPADDRv4 bytearray should be have 4-length bytes")

    ip_idx = 3

    while True:
        if ip_idx == -1:
            raise ValueError("Maximum ip count reached! invalid count")

        if ip_idx == 3:
            tmp = new_ip[ip_idx] + how_increase
        else:
            tmp = new_ip[ip_idx] + increase_next_sub_ip

        increase_next_sub_ip, remain = divmod(tmp, 0xFE)
        if increase_next_sub_ip == 0:
            new_ip[ip_idx] = remain
            break
        else:
            new_ip[ip_idx] = remain
            ip_idx -= 1

    return new_ip 



def calc_mac_increase(v_mac, how_increase):
    target_mac = bytearray(v_mac)
    if len(target_mac) != 6:
        raise ValueError("MAC-ADDR bytearray should be have 6-length bytes")

    mac_idx = 5

    while True:
        if mac_idx == -1:
            raise ValueError("Maximum MAC count reached! invalid count")

        if mac_idx == 5:
            tmp = target_mac[mac_idx] + how_increase
        else:
            tmp = target_mac[mac_idx] + increase_next_sub_mac

        increase_next_sub_mac, remain = divmod(tmp, 0xFF)
        if increase_next_sub_mac == 0:
            target_mac[mac_idx] = remain
            break
        else:
            target_mac[mac_idx] = remain
            mac_idx -= 1

    return target_mac


gen_count = input("Which do you want to how many create the PCAP (default:10)? ")
if len(gen_count) == 0:
    gen_count = 10
else:
    gen_count = int(gen_count)


new_scada_ip = input("Do you want to new SCADA IP? then input the new ip (10.10.100.1): ")
if len(new_scada_ip) == 0:
    new_scada_ip = get_ip_addr_bin("10.10.100.1")
else:
    new_scada_ip = get_ip_addr_bin(new_scada_ip)



new_scada_mac = input("Do you want to new SCADA MAC? then input the new MAC: ")
if len(new_scada_mac) == 0:
    new_scada_mac = scada_old_mac
else:
    new_scada_mac = get_mac_addr_bin(new_scada_mac)


new_slave_ip = input("Do you want to new Slave IP? then input the new ip: ")
if len(new_slave_ip) == 0:
    new_slave_ip = slave_ip
else:
    new_slave_ip = get_ip_addr_bin(new_slave_ip)



new_slave_mac = input("Do you want to new Slave MAC? then input the new MAC: ")
if len(new_slave_mac) == 0:
    new_slave_mac = slave_old_mac
else:
    new_slave_mac = get_mac_addr_bin(new_slave_mac)



for idx in range(1, gen_count+1):
    chnaged_slave_ip = calc_ip_increase(new_slave_ip, idx)
    print("CHANGED IP:  {:d}.{:d}.{:d}.{:d}".format(*tuple(chnaged_slave_ip)))

    if chnaged_slave_ip[3] == 0:
        print("The changed ip is invalid, skipping")
        gen_count += 1
        continue

    if chnaged_slave_ip == new_scada_ip:
        print("The changed ip is duplicated the SCADA IP, skipping")
        gen_count += 1
        continue

    changed_slave_mac = calc_mac_increase(new_slave_mac, idx)
    if changed_slave_mac == new_scada_mac:
        print("The SCADA MAC is duplicated the SCADA MAC, skipping")
        gen_count += 1
        continue

    pos = 0
    new_data = data.copy()

    while True:
        if pos + 1 >= len(data):
            break
    
        if data[pos:pos+6] == slave_old_mac:
            for i in range(6):
                new_data[pos+i] = changed_slave_mac[i]
            pos += 6
            continue

        if data[pos:pos+6] == scada_old_mac:
            for i in range(6):
                new_data[pos+i] = new_scada_mac[i]
            pos += 6
            continue

        if data[pos:pos+4] == scada_ip:
            for i in range(4):
                new_data[pos+i] = new_scada_ip[i]
            pos += 4
            continue

        if data[pos:pos+4] == slave_ip:
            for i in range(4):
                new_data[pos+i] = chnaged_slave_ip[i]
            pos += 4
            continue
        
        pos += 1

    print("CHANGED SLAVE IP:  {:d}.{:d}.{:d}.{:d}".format(*tuple(chnaged_slave_ip)))
    print("CHNAGED SLAVE MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*tuple(changed_slave_mac)))
    print("CHANGED SCADA IP:  {:d}.{:d}.{:d}.{:d}".format(*tuple(new_scada_ip)))
    print("CHNAGED SCADA MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*tuple(new_scada_mac)))

    path, filename = os.path.split(sys.argv[1])

    protocol_name = filename.replace('_all_mac_changed.pcap', '')
    full_filename = protocol_name + "_asset_{}.pcap".format(idx)
    print("NEW FILEPATH: {}".format(path + "asset/{}/".format(protocol_name) + full_filename))
    
    if not os.path.exists(path + "asset/{}/".format(protocol_name)):
        os.makedirs(path + "asset/{}/".format(protocol_name))

    write_fp = open(path + "asset/{}/".format(protocol_name) + full_filename, 'wb+')
    write_fp.write(new_data)
    write_fp.close()