# Packet Sniffer

A lightweight network packet sniffer for Linux that captures and analyzes network packets in real-time.

## Features

- **Packet Capture**: Captures raw network packets from the network interface
- **Protocol Support**: Analyzes Ethernet, IP, TCP, and UDP protocols
- **TCP Analysis**: Displays TCP port information and flags (SYN, ACK, FIN, RST, PSH)
- **UDP Analysis**: Shows UDP port and length information
- **Payload Display**: Displays first 80 characters of packet payload (printable characters only)

## Requirements

- Linux operating system
- GCC compiler
- Root privileges (for raw socket access)

## Compilation

```bash
gcc -o sniffer sniffer.c
```

## Usage

Run with root privileges:

```bash
sudo ./sniffer
```

The program will start capturing and displaying network packets in real-time. Each packet shows:
- Ethernet frame information
- Source and destination IP addresses
- Protocol type (TCP/UDP)
- Port information
- TCP flags (if applicable)
- Payload preview

Press `Ctrl+C` to stop the packet capture.

## Example Output

```
------- Ethernet Frame ----
  Dest MAC : 00:11:22:33:44:55
  Src MAC  : aa:bb:cc:dd:ee:ff
  Protocol : IP
------- IPv4 Header -------
  Src IP   : 192.168.1.100
  Dst IP   : 192.168.1.1
  Protocol : TCP
------ TCP ------------
  Src Port : 54321
  Dst Port : 443
  Flags    : SYN ACK 
  Payload  : ...
```

## Notes

- Requires root/sudo access to capture raw packets
- The program displays limited payload data (80 characters) for readability
- Useful for network troubleshooting and protocol analysis
