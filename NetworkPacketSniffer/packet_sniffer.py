# works for unix based system only
# needs sudo privilege
import socket
import struct
# from scapy.all import *


def main():
    connection = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        org_data, addr = connection.recvfrom(65565)

        dest_mac, src_mac, eth_proto, org_data = ethernet_unpack(org_data)
        print('\n Ethernet Frame: ')
        print('Destination: {}, Source: {}, Protocol: {}'.format(
            dest_mac, src_mac, eth_proto))

        # for ipv4
        if eth_proto == 8:
            (version, header_length, ttl, protocol,
             src, target, data) = ipv4_pack(org_data)
            print('\nIPv4 Packet:')
            print('\tVersion: {}, Header Length: {}, TTL: {}'.format(
                version, header_length, ttl))
            print('\tProtocol: {}, Source: {}, Target: {}'.format(
                protocol, src, target))
# unpacking ethernet frame


def ethernet_unpack(raw_data):
    dest_address, src_address, proto = struct.unpack(
        '! 6s 6s H', raw_data[:14])
    return get_mac(dest_address), get_mac(src_address), socket.htons(proto), raw_data[14:]

# mac address with proper formatting


def get_mac(addr_bytes):
    addr_str = map('{:02x}'.format, addr_bytes)
    formatted_mac = ':'.join(addr_str).upper()
    return formatted_mac

# Unpacking ipv4 packet


def ipv4_pack(data):
    version_length = data[0]
    version = version_length >> 4
    header_length = (version_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x BB 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, ipv4(src), ipv4(target), data[header_length:]

# return formatted ipv4 address


def ipv4(address):
    return '.'.join(map(str, address))

# Unpacking ICMP packet


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#unpack TCP segment
def tcp_segmet(data):
    (src_port, dest_port, sequence, acknowledgement,offset_reserved_flags) = struct.unpack('! H H L L H'data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin =  offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    





main()
