import socket
import struct
import textwrap

def ethernet_frame(data):
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(destination_mac), get_mac_addr(source_mac), socket.htons(protocol), data[14:]

def get_mac_addr(bytes_addr):
    bytes_string = map("{:02x}".format, bytes_addr)
    mac_addr = ':'.join(bytes_addr).upper()
    return mac_addr