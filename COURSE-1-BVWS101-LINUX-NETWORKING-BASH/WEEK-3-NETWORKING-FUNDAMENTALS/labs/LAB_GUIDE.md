# LAB-1.3.6: Network Diagrams and Subnetting Exercises

## Lab Overview

**Course:** BVWS101 – Foundations of Linux, Networking & Bash Scripting  
**Lab Code:** LAB-1.3.6  
**Lab Title:** Network Diagrams and Subnetting Exercises  
**Duration:** 3-4 hours  
**Difficulty:** Intermediate  
**Objectives:** Master TCP/IP fundamentals, subnetting calculations, network tools, and packet analysis for web application security testing.

---

## Lab Introduction

Network knowledge is essential for web application security professionals. You'll need to understand how data flows through networks, identify network-based attacks, and use network tools for reconnaissance and testing.

### Learning Objectives

By completing this lab, you will be able to:
- Understand TCP/IP protocol stack and OSI model
- Perform subnetting calculations manually and with tools
- Use network diagnostic tools (ping, traceroute, netstat, ss)
- Analyze network traffic with tcpdump and Wireshark
- Identify common network security issues
- Map network topology and document infrastructure
- Understand ports, protocols, and services

---

## Lab Setup

### Prerequisites
- Kali Linux VM or Ubuntu/Debian system
- Network connectivity
- Root/sudo access
- Basic understanding of IP addressing

### Required Tools

```bash
# Install network tools
sudo apt update
sudo apt install -y \
    net-tools \
    iproute2 \
    iputils-ping \
    traceroute \
    nmap \
    tcpdump \
    wireshark \
    netcat \
    dnsutils \
    whois \
    curl \
    wget

# Verify installations
ping -c 1 8.8.8.8
nmap --version
tcpdump --version
```

---

## Part 1: TCP/IP and OSI Model (30 minutes)

### Exercise 1.1: Understanding Network Layers

**OSI Model (7 Layers):**

| Layer | Name | Function | Protocols/Examples |
|-------|------|----------|-------------------|
| 7 | Application | User interface | HTTP, FTP, SSH, DNS |
| 6 | Presentation | Data formatting | SSL/TLS, JPEG, ASCII |
| 5 | Session | Connection management | NetBIOS, RPC |
| 4 | Transport | End-to-end delivery | TCP, UDP |
| 3 | Network | Routing | IP, ICMP, ARP |
| 2 | Data Link | Physical addressing | Ethernet, Wi-Fi |
| 1 | Physical | Hardware transmission | Cables, Radio |

**TCP/IP Model (4 Layers):**

| Layer | OSI Equivalent | Protocols |
|-------|----------------|-----------|
| Application | 5-7 | HTTP, FTP, SSH, DNS, SMTP |
| Transport | 4 | TCP, UDP |
| Internet | 3 | IP, ICMP, ARP |
| Network Access | 1-2 | Ethernet, Wi-Fi |

**Task 1:** Map a web request to layers

```
User types: https://example.com

Layer 7 (Application): HTTP/HTTPS request formed
Layer 6 (Presentation): SSL/TLS encryption applied
Layer 5 (Session): TCP session established
Layer 4 (Transport): TCP segments created (port 443)
Layer 3 (Network): IP packets created (destination IP)
Layer 2 (Data Link): Ethernet frames created (MAC addresses)
Layer 1 (Physical): Electrical signals on wire
```

---

### Exercise 1.2: Common Protocols and Ports

**Task 2:** Memorize essential ports

```bash
# Well-known ports (0-1023)
20/21   - FTP (File Transfer Protocol)
22      - SSH (Secure Shell)
23      - Telnet (Insecure remote access)
25      - SMTP (Email sending)
53      - DNS (Domain Name System)
80      - HTTP (Web traffic)
110     - POP3 (Email retrieval)
143     - IMAP (Email retrieval)
443     - HTTPS (Secure web traffic)
3306    - MySQL Database
3389    - RDP (Remote Desktop)
5432    - PostgreSQL Database
8080    - HTTP Alternate

# View common ports
cat /etc/services | head -50

# Check which ports are listening
sudo netstat -tuln
# Or modern alternative
sudo ss -tuln

# Check specific port
sudo lsof -i :80
sudo ss -tulnp | grep :443
```

---

## Part 2: IP Addressing and Subnetting (60 minutes)

### Exercise 2.1: IP Address Classes

**IPv4 Address Structure:**
- 32 bits divided into 4 octets
- Format: xxx.xxx.xxx.xxx (0-255 each)
- Network portion + Host portion

**Address Classes:**

| Class | Range | Default Mask | Networks | Hosts/Network |
|-------|-------|--------------|----------|---------------|
| A | 1-126 | 255.0.0.0 (/8) | 126 | 16,777,214 |
| B | 128-191 | 255.255.0.0 (/16) | 16,384 | 65,534 |
| C | 192-223 | 255.255.255.0 (/24) | 2,097,152 | 254 |
| D | 224-239 | Multicast | - | - |
| E | 240-255 | Reserved | - | - |

**Private IP Ranges (RFC 1918):**
- Class A: 10.0.0.0/8
- Class B: 172.16.0.0/12
- Class C: 192.168.0.0/16

**Task 3:** Identify address classes

```bash
# Your IP address
ip addr show
# Or
ifconfig

# Identify class:
# 10.0.0.1 = Class A (private)
# 172.16.0.1 = Class B (private)
# 192.168.1.1 = Class C (private)
# 8.8.8.8 = Class A (public)
```

---

### Exercise 2.2: Subnet Masks and CIDR Notation

**Subnet Mask Conversion:**

| CIDR | Subnet Mask | Hosts | Binary |
|------|-------------|-------|--------|
| /8 | 255.0.0.0 | 16,777,214 | 11111111.00000000.00000000.00000000 |
| /16 | 255.255.0.0 | 65,534 | 11111111.11111111.00000000.00000000 |
| /24 | 255.255.255.0 | 254 | 11111111.11111111.11111111.00000000 |
| /25 | 255.255.255.128 | 126 | 11111111.11111111.11111111.10000000 |
| /26 | 255.255.255.192 | 62 | 11111111.11111111.11111111.11000000 |
| /27 | 255.255.255.224 | 30 | 11111111.11111111.11111111.11100000 |
| /28 | 255.255.255.240 | 14 | 11111111.11111111.11111111.11110000 |
| /29 | 255.255.255.248 | 6 | 11111111.11111111.11111111.11111000 |
| /30 | 255.255.255.252 | 2 | 11111111.11111111.11111111.11111100 |

**Formula:**
- Hosts per subnet = 2^(32-prefix) - 2
- Number of subnets = 2^(borrowed bits)

**Task 4:** Calculate subnet information

```bash
# Example: 192.168.1.0/24

Network Address: 192.168.1.0
Broadcast Address: 192.168.1.255
First Usable Host: 192.168.1.1
Last Usable Host: 192.168.1.254
Total Hosts: 254
Subnet Mask: 255.255.255.0

# Use ipcalc tool
sudo apt install ipcalc -y
ipcalc 192.168.1.0/24

# Or sipcalc for more details
sudo apt install sipcalc -y
sipcalc 192.168.1.0/24
```

---

### Exercise 2.3: Subnetting Practice

**Task 5:** Subnet a Class C network

**Problem:** Divide 192.168.10.0/24 into 4 subnets

```
Original: 192.168.10.0/24 (254 hosts)
Need: 4 subnets
Borrowed bits: 2 (2^2 = 4 subnets)
New prefix: /24 + 2 = /26
Hosts per subnet: 2^(32-26) - 2 = 62 hosts

Subnet 1: 192.168.10.0/26
  Network: 192.168.10.0
  First Host: 192.168.10.1
  Last Host: 192.168.10.62
  Broadcast: 192.168.10.63

Subnet 2: 192.168.10.64/26
  Network: 192.168.10.64
  First Host: 192.168.10.65
  Last Host: 192.168.10.126
  Broadcast: 192.168.10.127

Subnet 3: 192.168.10.128/26
  Network: 192.168.10.128
  First Host: 192.168.10.129
  Last Host: 192.168.10.190
  Broadcast: 192.168.10.191

Subnet 4: 192.168.10.192/26
  Network: 192.168.10.192
  First Host: 192.168.10.193
  Last Host: 192.168.10.254
  Broadcast: 192.168.10.255
```

**Verify with tools:**

```bash
# Calculate each subnet
for subnet in 0 64 128 192; do
    echo "Subnet: 192.168.10.$subnet/26"
    ipcalc 192.168.10.$subnet/26
    echo "---"
done
```

---

### Exercise 2.4: VLSM (Variable Length Subnet Masking)

**Task 6:** Design network with different subnet sizes

**Scenario:** Company needs:
- 100 hosts for Sales
- 50 hosts for IT
- 25 hosts for HR
- 10 hosts for Management

**Solution using 192.168.1.0/24:**

```
Sales (100 hosts): Need /25 (126 hosts)
  192.168.1.0/25
  Range: 192.168.1.1 - 192.168.1.126

IT (50 hosts): Need /26 (62 hosts)
  192.168.1.128/26
  Range: 192.168.1.129 - 192.168.1.190

HR (25 hosts): Need /27 (30 hosts)
  192.168.1.192/27
  Range: 192.168.1.193 - 192.168.1.222

Management (10 hosts): Need /28 (14 hosts)
  192.168.1.224/28
  Range: 192.168.1.225 - 192.168.1.238
```

---

## Part 3: Network Diagnostic Tools (45 minutes)

### Exercise 3.1: Ping and ICMP

**Task 7:** Use ping for connectivity testing

```bash
# Basic ping
ping -c 4 8.8.8.8

# Ping with timestamp
ping -c 4 -D 8.8.8.8

# Ping with specific packet size
ping -c 4 -s 1000 8.8.8.8

# Ping sweep (scan subnet)
for i in {1..254}; do
    ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i is up"
done

# Or use nmap
nmap -sn 192.168.1.0/24

# Flood ping (requires root)
sudo ping -f 8.8.8.8

# Set TTL
ping -c 4 -t 64 8.8.8.8
```

**Understanding ping output:**
```
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=10.2 ms
│                       │          │        │
│                       │          │        └─ Round-trip time
│                       │          └─ Time To Live (hops remaining)
│                       └─ Sequence number
└─ Packet size
```

---

### Exercise 3.2: Traceroute

**Task 8:** Trace network path

```bash
# Traceroute to destination
traceroute google.com

# Traceroute with ICMP
sudo traceroute -I google.com

# Traceroute with TCP
sudo traceroute -T -p 443 google.com

# MTR (My TraceRoute) - continuous traceroute
sudo apt install mtr -y
mtr google.com

# Traceroute with specific interface
traceroute -i eth0 8.8.8.8
```

**Understanding traceroute:**
```
1  192.168.1.1 (192.168.1.1)  1.234 ms  # Your router
2  10.0.0.1 (10.0.0.1)  5.678 ms      # ISP gateway
3  * * *                                # Firewall blocking
4  8.8.8.8 (8.8.8.8)  10.123 ms       # Destination
```

---

### Exercise 3.3: Netstat and SS

**Task 9:** View network connections

```bash
# All listening ports
sudo netstat -tuln

# All connections
sudo netstat -tun

# With process names
sudo netstat -tulnp

# Routing table
netstat -rn
# Or
route -n
# Or modern
ip route show

# Network statistics
netstat -s

# Modern alternative: ss (socket statistics)
sudo ss -tuln          # Listening ports
sudo ss -tun           # All connections
sudo ss -tulnp         # With processes
sudo ss -s             # Statistics

# Show only TCP
sudo ss -t

# Show only UDP
sudo ss -u

# Filter by port
sudo ss -tuln | grep :80

# Show established connections
sudo ss -t state established
```

---

### Exercise 3.4: Network Interface Configuration

**Task 10:** View and configure network interfaces

```bash
# View interfaces (old way)
ifconfig

# View interfaces (new way)
ip addr show
ip a

# View specific interface
ip addr show eth0

# View link status
ip link show

# Enable/disable interface
sudo ip link set eth0 down
sudo ip link set eth0 up

# Add IP address
sudo ip addr add 192.168.1.100/24 dev eth0

# Remove IP address
sudo ip addr del 192.168.1.100/24 dev eth0

# View routing table
ip route show

# Add route
sudo ip route add 10.0.0.0/24 via 192.168.1.1

# Add default gateway
sudo ip route add default via 192.168.1.1

# View ARP cache
ip neigh show
# Or
arp -a

# View DNS configuration
cat /etc/resolv.conf
```

---

## Part 4: Packet Analysis (60 minutes)

### Exercise 4.1: TCPDump Basics

**Task 11:** Capture and analyze packets

```bash
# List interfaces
sudo tcpdump -D

# Capture on specific interface
sudo tcpdump -i eth0

# Capture with count limit
sudo tcpdump -i eth0 -c 10

# Save to file
sudo tcpdump -i eth0 -w capture.pcap

# Read from file
sudo tcpdump -r capture.pcap

# Verbose output
sudo tcpdump -i eth0 -v
sudo tcpdump -i eth0 -vv
sudo tcpdump -i eth0 -vvv

# Show packet contents in hex and ASCII
sudo tcpdump -i eth0 -X

# Don't resolve hostnames (faster)
sudo tcpdump -i eth0 -n

# Don't resolve ports
sudo tcpdump -i eth0 -nn
```

---

### Exercise 4.2: TCPDump Filters

**Task 12:** Use BPF filters to capture specific traffic

```bash
# Capture only TCP traffic
sudo tcpdump -i eth0 tcp

# Capture only UDP traffic
sudo tcpdump -i eth0 udp

# Capture only ICMP (ping)
sudo tcpdump -i eth0 icmp

# Capture specific host
sudo tcpdump -i eth0 host 8.8.8.8

# Capture specific source
sudo tcpdump -i eth0 src 192.168.1.100

# Capture specific destination
sudo tcpdump -i eth0 dst 8.8.8.8

# Capture specific port
sudo tcpdump -i eth0 port 80

# Capture specific source port
sudo tcpdump -i eth0 src port 443

# Capture port range
sudo tcpdump -i eth0 portrange 80-443

# Capture specific network
sudo tcpdump -i eth0 net 192.168.1.0/24

# Combine filters with AND
sudo tcpdump -i eth0 'host 8.8.8.8 and port 80'

# Combine filters with OR
sudo tcpdump -i eth0 'port 80 or port 443'

# Exclude traffic
sudo tcpdump -i eth0 'not port 22'

# Capture HTTP GET requests
sudo tcpdump -i eth0 -s 0 -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Capture SYN packets
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# Capture HTTP traffic
sudo tcpdump -i eth0 -A -s 0 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

---

### Exercise 4.3: Wireshark Analysis

**Task 13:** Analyze captured traffic with Wireshark

```bash
# Start Wireshark (GUI)
sudo wireshark &

# Or capture first, then analyze
sudo tcpdump -i eth0 -w http_traffic.pcap
wireshark http_traffic.pcap
```

**Wireshark Display Filters:**

```
# HTTP traffic
http

# Specific IP
ip.addr == 192.168.1.100

# Specific source IP
ip.src == 192.168.1.100

# Specific destination IP
ip.dst == 8.8.8.8

# Specific port
tcp.port == 80

# TCP SYN packets
tcp.flags.syn == 1

# TCP RST packets
tcp.flags.reset == 1

# DNS queries
dns.flags.response == 0

# DNS responses
dns.flags.response == 1

# Follow TCP stream
Right-click packet > Follow > TCP Stream

# Export HTTP objects
File > Export Objects > HTTP
```

**Analysis Tasks:**
1. Identify three-way handshake (SYN, SYN-ACK, ACK)
2. Find HTTP GET/POST requests
3. Extract credentials from unencrypted traffic
4. Identify suspicious traffic patterns

---

## Part 5: Network Scanning and Reconnaissance (45 minutes)

### Exercise 5.1: Nmap Basics

**Task 14:** Scan networks with Nmap

```bash
# Ping scan (host discovery)
nmap -sn 192.168.1.0/24

# TCP SYN scan (stealth scan)
sudo nmap -sS 192.168.1.1

# TCP connect scan
nmap -sT 192.168.1.1

# UDP scan
sudo nmap -sU 192.168.1.1

# Scan specific ports
nmap -p 80,443 192.168.1.1

# Scan port range
nmap -p 1-1000 192.168.1.1

# Scan all ports
nmap -p- 192.168.1.1

# Fast scan (top 100 ports)
nmap -F 192.168.1.1

# Service version detection
nmap -sV 192.168.1.1

# OS detection
sudo nmap -O 192.168.1.1

# Aggressive scan
sudo nmap -A 192.168.1.1

# Save output
nmap -oN scan_results.txt 192.168.1.1
nmap -oX scan_results.xml 192.168.1.1

# Scan multiple hosts
nmap 192.168.1.1 192.168.1.2 192.168.1.3
nmap 192.168.1.1-10
nmap 192.168.1.0/24

# Exclude hosts
nmap 192.168.1.0/24 --exclude 192.168.1.1
```

---

### Exercise 5.2: DNS Reconnaissance

**Task 15:** Gather DNS information

```bash
# DNS lookup
nslookup google.com

# Detailed DNS query
dig google.com

# Query specific record type
dig google.com A      # IPv4 address
dig google.com AAAA   # IPv6 address
dig google.com MX     # Mail servers
dig google.com NS     # Name servers
dig google.com TXT    # Text records
dig google.com SOA    # Start of Authority

# Reverse DNS lookup
dig -x 8.8.8.8

# Query specific DNS server
dig @8.8.8.8 google.com

# Short output
dig +short google.com

# Trace DNS resolution
dig +trace google.com

# DNS zone transfer (if allowed)
dig @ns1.example.com example.com AXFR

# WHOIS lookup
whois google.com
whois 8.8.8.8

# Host command
host google.com
host -t MX google.com
```

---

## Part 6: Lab Challenge (30 minutes)

### Challenge: Network Security Audit

**Scenario:** You've been hired to audit a company's network. Perform reconnaissance and document findings.

**Tasks:**

1. **Network Discovery:**
   - Identify all live hosts on 192.168.1.0/24
   - Document IP addresses and hostnames

2. **Port Scanning:**
   - Scan all hosts for open ports
   - Identify running services
   - Detect OS versions

3. **Traffic Analysis:**
   - Capture 5 minutes of network traffic
   - Identify protocols in use
   - Find any unencrypted credentials

4. **Documentation:**
   - Create network diagram
   - List all findings
   - Provide security recommendations

**Solution Framework:**

```bash
# 1. Host discovery
nmap -sn 192.168.1.0/24 -oN hosts.txt

# 2. Port scanning
nmap -sS -sV -O -p- 192.168.1.0/24 -oA full_scan

# 3. Traffic capture
sudo tcpdump -i eth0 -w audit.pcap -G 300 -W 1

# 4. Analysis
wireshark audit.pcap

# Generate report
nmap --script vuln 192.168.1.0/24 -oN vulnerability_scan.txt
```

---

## Verification and Testing

### Checklist

- [ ] Understand OSI and TCP/IP models
- [ ] Can perform subnetting calculations
- [ ] Can use ping, traceroute, netstat/ss
- [ ] Can capture and analyze packets with tcpdump
- [ ] Can use Wireshark for traffic analysis
- [ ] Can perform network reconnaissance with nmap
- [ ] Can interpret DNS records
- [ ] Can document network topology

---

## Cleanup

```bash
# Remove capture files
rm -f *.pcap

# Or keep for reference
mkdir ~/fellowship-labs/week3
mv *.pcap ~/fellowship-labs/week3/
echo "Lab completed on $(date)" > ~/fellowship-labs/week3/completion.txt
```

---

## Submission Requirements

Submit:

1. **Subnetting Worksheet** - All calculations with verification
2. **Network Diagram** - Topology of scanned network
3. **Packet Analysis Report** - Wireshark findings
4. **Nmap Scan Results** - Complete scan outputs
5. **Reflection** (300-400 words) on networking concepts

---

## Additional Resources

- [TCP/IP Guide](https://www.tcpipguide.com/)
- [Subnet Calculator](https://www.subnet-calculator.com/)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Nmap Reference](https://nmap.org/book/man.html)

---

**Lab Version:** 1.0  
**Last Updated:** November 2025  
**Instructor Contact:** resources@aivtic.org.ng

---

**End of Lab Guide**
