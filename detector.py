# NAME: Seunghun Oh
# CS 558 Lab 5 Part 3
# This program returns IP addresses whee there are three times more SYN calls than ACK calls.
# Collaborators: Brian Roach
# Number of Late Days on this Assignment: 1
# Total number of Late Days: 1

import dpkt
import socket
import sys

def detect(f):
    # Read PCAP file
    pcap = dpkt.pcap.Reader(f)
    # We will be storing logs in this list. [IP Addr, SYN Only, ACK Present]
    log = []

    # Iterate through timestamps and buffers in PCAP
    for ts, buf in pcap:
        # Ethernet and IP value
        eth = ""
        ip = ""

        # If there is no buffer data, skip the current packet
        if len(buf) == 0:
            continue

        # If current packet does not have Ethernet and if it's not IP type, skip it
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        # If current packet does not have Ethernet data and if its protocol isn't TCP, skip it
        try:
            ip = eth.data
        except:
            continue
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        # Find the SYN and ACK flags
        tcp = ip.data
        syn = (tcp.flags & dpkt.tcp.TH_SYN) != 0
        ack = (tcp.flags & dpkt.tcp.TH_ACK) != 0

        if syn and ack:
            dst_ip = str(socket.inet_ntoa(ip.dst))
            index = 0
            found = False
            for i in range(len(log)):
                if dst_ip == log[i][0]:
                    found = True
                    index = i
                    break

            if found:
                log[index][2] += 1
            else:
                log += [[dst_ip, False, True]]

        if syn and not ack:
            source_ip = str(socket.inet_ntoa(ip.src))
            index = 0
            found = False
            for i in range(len(log)):
                if source_ip == log[i][0]:
                    found = True
                    index = i
                    break

            if found:
                log[index][1] += 1
            else:
                log += [[source_ip, True, False]]

    # Iterate through the log to check instances where there are three times more SYN flags than ACK flags
    for ip in log:
        if ip[1] >= ip[2] * 3:
            print ip[0]


if __name__ == "__main__":
    file = open(sys.argv[1])
    detect(file)
