import socket
import struct
import textwrap

#unpack ethernet frame
def ethernet_frame(data):
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(destination_mac), get_mac_addr(source_mac), socket.htons(protocol), data[14:]

