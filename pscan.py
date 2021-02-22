#!/usr/bin/python3

import sys
from scapy.all import *


import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

target = str(sys.argv[1])
startport = int(sys.argv[2])
protocol = str(sys.argv[3])
sourceport = random.randint(1025,65534)

print ("Scanning target " + target + ":" + str(startport) + "using " + protocol)

packet = sr1(IP(dst=target)/TCP(sport=sourceport,dport=startport, flags="S"),timeout=10)
if(str(type(packet))=="<type 'NoneType'>"):
    print ("Closed")
elif(packet.haslayer(protocol)):
    if(packet.getlayer(protocol).flags == 0x12):
        send = sr(IP(dst=target)/TCP(sport=sourceport,dport=startport,flags="AR"),timeout=10)
        print ("Open")
        packet.pdfdump()
    elif (packet.getlayer(protocol).flags == 0x14):
        print ("Closed")
