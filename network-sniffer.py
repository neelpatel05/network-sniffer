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
	mac_addr = ':'.join(bytes_string).upper()
	return mac_addr

def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = (version_header_length & 15) * 4
	time_to_live, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	src_ipv4 = ipv4(source)
	target_ipv4 = ipv4(target)
	return version, header_length, time_to_live, protocol, src_ipv4, target_ipv4, data[header_length:]

def ipv4(addr):
	return ':'.join(map(str, addr))

def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]

def tcp_packet(data):
	(src_post, dest_post, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flag >> 12) * 4
	flag_urg =  (offset_reserved_flag & 32) >> 5
	flag_ack =  (offset_reserved_flag & 16) >> 5
	flag_psh =  (offset_reserved_flag & 8) >> 5
	flag_rst =  (offset_reserved_flag & 4) >> 5
	flag_syn =  (offset_reserved_flag & 2) >> 5
	flag_fin =  (offset_reserved_flag & 1
	return src_post, dest_post, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_packet(data):
	src_port, dest_port, checksum = struct.unpack('! B B H', data[:4])
	return src_port, dest_port, checksum, data[4:]

main()
