# Python Packet Sniffer

A Linux-based packet sniffer built from scratch in Python to understand
network protocols, packet structures, and network traffic analysis.

## Features

- Ethernet frame parsing
- IPv4 packet parsing
- TCP packet parsing
- UDP packet parsing
- ICMP packet parsing
- TCP flag analysis
- Basic HTTP detection
- DNS packet parsing
- DNS query extraction
- DNS query type detection
- Payload inspection

## Technologies

- Python 3
- Socket programming
- Struct module
- Linux raw sockets
- Networking protocols

## Protocols Currently Supported

| Protocol | Support |
|---|---|
| Ethernet | Yes |
| IPv4 | Yes |
| TCP | Yes |
| UDP | Yes |
| ICMP | Yes |
| HTTP detection | Basic |
| DNS | Basic |

## Requirements

- Linux
- Python 3
- Root privileges or appropriate packet-capture capabilities

## Usage

```bash
sudo python3 sniffer.py
