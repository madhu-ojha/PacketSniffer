import socket
import struct

# unpacking ethernet frame


def ethernet_unpack(raw_data):
    dest_address, src_address, proto = struct.unpack(
        '! 6s 6s H', raw_data[:14])
    return get_mac(dest_address), get_mac(src_address), socket.htons(proto), raw_data[14:]

# mac address with proper formatting


def get_mac(addr_bytes):
    addr_str = map('{:02x}'.format(), addr_bytes)
    formatted_mac = ':'.join(addr_str).upper()
    return formatted_mac
