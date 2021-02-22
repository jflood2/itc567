#!/usr/bin/python3

import sys
from scapy.all import *
import pyx

#set the logging level for scapy
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#get command line arguments and other variables
target = str(sys.argv[1])
startport = int(sys.argv[2])
protocol = "TCP"
sourceport = random.randint(1025,65534)

print ("Scanning target " + target + ":" + str(startport) + "using " + protocol)

#create the packet
packet = sr1(IP(dst=target)/TCP(sport=sourceport,dport=startport, flags="S"),timeout=10)

#check if the specified protocol is available
if(packet.haslayer(protocol)):
    #if the packet is sent and we get the flag 0x12, then the port is open. Then write a report to a pdf.
    if(packet.getlayer(protocol).flags == 0x12):
        send = sr(IP(dst=target)/TCP(sport=sourceport,dport=startport,flags="AR"),timeout=10)
        print (target + ":" + str(startport) + " is open")
        print ("\nWriting packets to report 'packets.pdf'")
        packet.pdfdump("packets.pdf")
    #if the port is closed then we will get the flag 0x14, 
    elif (packet.getlayer(protocol).flags == 0x14):
        print (target + ":" + str(startport) + " is closed")
