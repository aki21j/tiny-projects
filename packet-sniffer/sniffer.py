"""
The sniffer should be able to get:
- Destination and source MAC address
- Ethernet protocol
- Protocol used (e.g: 6 means its a TCP packet)
- TTL
- Header length
"""

import socket
import sys
import struct

PORT = 8888

try:
  listen_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
except socket.error:
  print("Socket could not be created")
  sys.exit(1)

def get_mac_address(mac):
  mac = map("{:02x}".format, mac)
  return ':'.join(mac).upper()

while True:
  raw_data, address = listen_socket.recvfrom(PORT)
  destination_mac, src_mac, ethernet_protocol = struct.unpack("! 6s 6s H",raw_data[:14])
  destination_mac = get_mac_address(destination_mac)
  src_mac = get_mac_address(src_mac)
  ethernet_protocol = socket.htons(ethernet_protocol)
  data = raw_data[:14]
  print(data)
  print('\nEthernet frame:')
  print('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, src_mac, ethernet_protocol))

  # IPV4 protocol
  if ethernet_protocol == 8:
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    src = '.'.join(map(str(src)))
    target = '.'.join(map(str(target)))

    print('IPv4 packet:')
    print('\tVersion: {}, Header length: {}, TTL: {}'.format(version,header_len,ttl))
    print('\tProtocol: {}, Source: {}, Target: {}'.format(proto,src,target))
