# CodeAlpha Task 1 — Basic Network Sniffer

## 📌 Project Overview

This project was developed as part of the **CodeAlpha Cyber Security Internship — Task 1: Basic Network Sniffer**.

The objective of this project is to build a Python-based network sniffer capable of capturing and analyzing live network packets using the **Scapy** library.

The sniffer displays useful packet information such as:

* Source and destination IP addresses
* Network protocols
* Source and destination ports
* Packet size
* TCP flags
* ARP requests and replies
* DNS queries
* TTL / Hop Limit values
* Payload previews in ASCII and hexadecimal format

The project is designed for educational purposes and authorized network analysis.

---

## 🎯 Objectives

* Capture live network traffic.
* Analyze the basic structure of network packets.
* Identify common network protocols.
* Display source and destination IP addresses.
* Display source and destination ports.
* Analyze TCP flags.
* Identify ARP requests and replies.
* Detect DNS queries.
* Display limited packet payload previews.
* Save captured traffic to a `.pcap` file for further analysis in Wireshark.
* Understand basic network communication between local systems and remote servers.

---

## 🛠️ Technologies Used

* **Python 3**
* **Scapy**
* **Wireshark** — optional tool for further `.pcap` analysis
* **Windows**

---

## 🔍 Features

### 1. Packet Capture

The program uses Scapy's `sniff()` function to capture live network packets.

```python
sniff(
    iface=args.iface,
    filter=args.filter or None,
    prn=process_packet,
    count=args.count,
    store=False
)
```

Packets can be captured until `Ctrl+C` is pressed or until a specified packet count is reached.

---

### 2. Protocol Detection

The sniffer can identify and analyze several common protocols, including:

* ARP
* IPv4
* IPv6
* TCP
* UDP
* ICMP
* DNS
* HTTP
* HTTPS/TLS traffic indicators

---

### 3. IP Address Analysis

For IP packets, the program displays:

```text
Source IP
Destination IP
Protocol
TTL / Hop Limit
```

Example:

```text
Source IP     : 192.168.0.62
Destination IP: 157.240.227.21
Protocol      : TCP
TTL            : 128
```

---

### 4. Port Analysis

For TCP and UDP packets, the program displays source and destination ports.

Example:

```text
Ports         : 56124 -> 443
```

Port `443` is commonly associated with encrypted web traffic.

---

### 5. TCP Flag Analysis

The program converts TCP flags into readable names such as:

* SYN
* ACK
* FIN
* RST
* PSH
* URG

Example:

```text
TCP Flags     : PSH,ACK
```

TCP flags provide information about the state and behavior of TCP connections.

---

### 6. ARP Analysis

ARP packets are separately analyzed to display:

```text
ARP Request / Reply
Sender IP
Sender MAC
Target IP
Target MAC
```

Example:

```text
Protocol : ARP (Request)
Sender   : 192.168.0.21
Target   : 192.168.0.88
```

ARP is used on local networks to resolve IPv4 addresses to MAC addresses.

---

### 7. DNS Query Detection

The sniffer can detect DNS queries and display the queried domain name.

Example:

```text
DNS Query     : google.com.
```

DNS normally uses UDP port `53` for standard DNS queries.

The project was also tested with multicast DNS (mDNS), which commonly uses UDP port `5353` and multicast address `224.0.0.251`.

Example:

```text
Ports         : 5353 -> 5353
DNS Query     : _ndi._tcp.local.
```

This represents local service discovery traffic associated with mDNS.

---

### 8. Payload Preview

When a packet contains a `Raw` layer, the program displays a limited payload preview in:

* ASCII format
* Hexadecimal format

Example:

```text
Payload       : .........p........2..I[.....eY.

hex: 170303001abaf6df11700cb388928be3a0e232abbc495bf816deedc56559d8
```

The payload output is intentionally limited to a small preview instead of displaying complete packet contents.

Encrypted traffic may appear as unreadable binary/hexadecimal data because the application payload is protected by encryption.

---

## ⚙️ Installation

### 1. Install Python

Verify that Python is installed:

```bash
python --version
```

---

### 2. Install Scapy

Install Scapy using pip:

```bash
pip install scapy
```

Verify the installation:

```bash
python -c "import scapy; print('Scapy OK')"
```

Expected output:

```text
Scapy OK
```

---

## 🚀 Usage

Run the sniffer with:

```bash
python network_sniffer.py
```

The program will start capturing packets and display their information in the terminal.

Press:

```text
CTRL + C
```

to stop packet capture.

---

## 🔧 Command-Line Options

### Specify Network Interface

```bash
python network_sniffer.py -i "Interface Name"
```

### Capture a Specific Number of Packets

For example, capture 100 packets:

```bash
python network_sniffer.py -c 100
```

### Capture Only TCP Traffic

```bash
python network_sniffer.py -f "tcp"
```

### Capture UDP DNS Traffic

```bash
python network_sniffer.py -f "udp port 53"
```

### Capture Traffic to/from a Specific Host

```bash
python network_sniffer.py -f "host 8.8.8.8"
```

### Save Packets to a PCAP File

```bash
python network_sniffer.py -c 100 -w capture.pcap
```

The resulting `.pcap` file can be opened in **Wireshark** for deeper packet analysis.

---

## 📊 Test Results

The sniffer was successfully tested against live network traffic in a local test environment.

During one capture session, the program recorded:

```text
Total packets captured: 136

UDP      : 70
ARP      : 31
HTTPS    : 26
TCP      : 4
DNS      : 3
```

The captured traffic included ARP, TCP, UDP, HTTPS, and DNS/mDNS-related traffic.

### ARP

Example:

```text
Protocol : ARP (Request)
Sender   : 192.168.0.21
Target   : 192.168.0.88
```

### TCP/HTTPS

Example:

```text
Source IP     : 192.168.0.62
Destination IP: 157.240.227.21
Ports         : 56124 -> 443
TCP Flags     : PSH,ACK
```

TCP port `443` was identified as HTTPS traffic by the sniffer.

### UDP

Example:

```text
Source IP     : 192.168.0.62
Destination IP: 142.250.200.174
Ports         : 63963 -> 443
```

UDP traffic using port `443` can be associated with modern encrypted protocols such as **QUIC/HTTP/3**.

### DNS / mDNS

Example:

```text
Ports         : 5353 -> 5353
DNS Query     : _ndi._tcp.local.
```

This represents multicast DNS (mDNS) service discovery traffic.

---

## 🔐 Security and Privacy Considerations

Network sniffing can expose sensitive network information.

This tool should only be used on:

* Your own system
* Your own lab environment
* Networks where you have explicit authorization to capture traffic

Do not capture or inspect network traffic belonging to other users or systems without permission.

This project was developed for **educational and authorized cybersecurity testing purposes**.

---

## 🧠 Key Learning Outcomes

Through this project, I gained practical experience with:

* Network packet capture
* Packet structure and network layers
* IPv4 and IPv6 traffic
* ARP communication
* TCP and UDP protocols
* TCP flag analysis
* Port analysis
* DNS and mDNS traffic
* Payload representation
* Encrypted network traffic
* Python-based network analysis
* Scapy packet inspection
* PCAP generation
* Wireshark-based packet analysis

---

## 📸 Project Evidence

Screenshots demonstrating the working network sniffer are included in the `screenshots` directory.

### 1. Network Sniffer Running

![Network Sniffer Running](screenshots/01_sniffer_running.png)

### 2. ARP Packet Analysis

![ARP Packet Analysis](screenshots/02_arp_packets.png)

### 3. TCP/HTTPS Packet Analysis

![TCP HTTPS Packet Analysis](screenshots/03_tcp_https.png)

### 4. UDP Packet Analysis

![UDP Packet Analysis](screenshots/04_udp_packets.png)

### 5. DNS Query Detection

![DNS Query Detection](screenshots/05_dns_query.png)

### 6. Capture Summary

![Capture Summary](screenshots/06_capture_summary.png)

---

## 📁 Project Structure

```text
CodeAlpha_Task1/
│
├── network_sniffer.py
├── README.md
│
└── screenshots/
    ├── 01_sniffer_running.png
    ├── 02_arp_packets.png
    ├── 03_tcp_https.png
    ├── 04_udp_packets.png
    ├── 05_dns_query.png
    └── 06_capture_summary.png
```

---

## 👩‍💻 Internship Task

**Program:** CodeAlpha Cyber Security Internship

**Task:** Task 1 — Basic Network Sniffer

**Domain:** Cyber Security / Network Security

**Primary Technology:** Python + Scapy

---

## ⚠️ Note

The packet output shown in this project represents traffic captured from a local test environment.

Payloads from encrypted connections are not expected to reveal readable application content because encryption protects the transmitted data.

This project is intended for educational and authorized network security testing only.
