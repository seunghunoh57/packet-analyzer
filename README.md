# Network Packet Analyzer
A program that analyzes specific network patterns from a captured network packet (.pcap)

### How it works

This program (currently) specifically analyzes TCP/IP calls where there are three times more SYN calls than ACK calls. It then returns the corresponding IP addresses. The item to be detected can be changed!

### How to run
To run, make sure there is a .pcap file in the same directory and enter the following into the terminal:
```python
python detector.py file.pcap
```
