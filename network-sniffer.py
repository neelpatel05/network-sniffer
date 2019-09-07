import socket
import struct
import textwrap

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        destination_mac, source_mac, protocol, data = ethernet_frame(raw_data)
        print("\nEthernet Frame: ")
        print("Destination: {}, Source: {}, Protocol: {}".format(destination_mac, source_mac, protocol))

def ethernet_frame(data):
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(destination_mac), get_mac_addr(source_mac), socket.htons(protocol), data[14:]

def get_mac_addr(bytes_addr):
    bytes_string = map("{:02x}".format, bytes_addr)
    mac_addr = ':'.join(bytes_addr).upper()
    return mac_addr

main()