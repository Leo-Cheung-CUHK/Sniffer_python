## Port to service 
## Port 80 - HTTP
## Port 21 - FTP
## Port 443 - HTTPS


import socket, sys
from struct import *
import codecs
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
# receive a packet
def CheckIPPacket(ip_packet):
    packet = ip_packet

    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
 
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
        version_ihl = iph[0]

        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
 
        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

        TOS = iph[1]& 0xF  # Exstract the final 4 bits   
        if TOS ==0:
            return 'Leaky Bucket'
        elif TOS ==1:
            return 'VOIP'
        elif TOS ==2:
            return 'FTP'
        elif TOS ==3:
            retun 'HTTP'
        else:
            print 'TOS Number Exceed Index'
