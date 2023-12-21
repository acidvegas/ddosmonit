# DDoS Monit

## Description
This Packet Analysis Tool is designed to capture and analyze network packets in real-time. It provides detailed insights into the traffic flowing through a network interface, including information about protocols, IP addresses, port numbers, packet length, Time-To-Live (TTL), window size, and checksum validation. This tool is particularly useful for network debugging, security analysis, and traffic monitoring.

## Features
- Real-time packet capturing on specified network interfaces.
- Supports analysis of TCP, UDP, and ICMP protocols.
- Displays packet details such as source/destination IP, source/destination port, packet length, and TTL.
- Identifies and displays printable payloads in network traffic.

## Usage
| Argument | Description                                                 |
| -------- | ----------------------------------------------------------- |
| `-d`     | Specify the network device to monitor *(e.g., eth0)*.       |
| `-c`     | Set the packets-per-second threshold for logging.           |
| `-x`     | Provide a comma-separated list of IPs and ports to exclude. |
| `-i`     | Provide a comma-separated list of IPs and ports to include. |