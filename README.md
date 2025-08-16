
# Packet Parser

A comprehensive network packet capture and analysis tool written in C that provides real-time monitoring and detailed parsing of network traffic.

## 🚀 Features

- **Multi-Protocol Support**: Analyzes TCP, UDP, and DNS packets
- **Multi-Link Layer Support**: Handles Ethernet, 802.11, and Radiotap frames
- **Real-Time Monitoring**: Live packet capture with immediate console output
- **Comprehensive Logging**: Dual output to console and file for analysis
- **DNS Deep Analysis**: Detailed parsing of DNS queries and responses
- **Cross-Platform**: Works on Linux systems with libpcap support

## 📋 Prerequisites

- **Operating System**: Linux (tested on Ubuntu/Debian)
- **Compiler**: GCC (GNU Compiler Collection)
- **Library**: libpcap development package
- **Permissions**: Root/sudo access for packet capture

## 🔧 Installation

### 1. Install Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential libpcap-dev

# CentOS/RHEL/Fedora
sudo yum install gcc make libpcap-devel
# or
sudo dnf install gcc make libpcap-devel
```

### 2. Clone and Build

```bash
# Clone the repository
git clone <your-repository-url>
cd Packet_Parser

# Build the project
make

# The binary 'packet_parser' will be created
```

## 🎯 Usage

### Basic Usage

```bash
# Run packet capture on a network interface
sudo ./packet_parser <interface_name>

# Examples
sudo ./packet_parser eth0          # Ethernet interface
sudo ./packet_parser wlan0         # Wireless interface
sudo ./packet_parser any           # Any available interface
```

### Command Line Arguments

- **Interface Name**: Specify the network interface to monitor
- **Root Access**: Required for packet capture in promiscuous mode

### Output

The tool provides real-time output in two formats:

1. **Console Output**: Immediate display of captured packets
2. **File Output**: Persistent logging to `output.txt`

## 📊 Supported Protocols

### TCP Analysis
- Source and destination IP addresses
- Source and destination ports
- Protocol identification
- Connection tracking

### UDP Analysis
- Basic UDP packet information
- Port-based protocol detection
- DNS traffic identification

### DNS Deep Parsing
- Query/Response identification
- Domain name extraction
- DNS flags analysis (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
- Record counts (Questions, Answers, Authority, Additional)
- Query types and classes

## 🏗️ Project Structure

```
Packet_Parser/
├── inc/                    # Header files
│   ├── packet_parser.h    # Main packet parsing interface
│   ├── tcp_parser.h       # TCP packet parsing
│   ├── udp_parser.h       # UDP packet parsing
│   └── dns_parser.h       # DNS packet parsing
├── src/                    # Source code
│   ├── main.c             # Main program entry point
│   ├── packet_parser.c    # Main packet handler
│   ├── tcp_parser.c       # TCP packet analysis
│   ├── udp_parser.c       # UDP packet analysis
│   └── dns_parser.c       # DNS packet analysis
├── util/                   # Utility functions
│   ├── inc/logger.h       # Logging interface
│   └── src/logger.c       # Logging implementation
├── Makefile               # Build configuration
├── README.md              # This file
└── output.txt             # Captured packet logs
```

## 🔍 Sample Output

### TCP Traffic
```
[TCP] SrcIP=192.168.1.100, SrcPort=51234, DstIP=8.8.8.8, DstPort=443, Protocol=TCP
```

### UDP Traffic
```
[UDP] SrcIP=192.168.1.100, SrcPort=5353, DstIP=224.0.0.251, DstPort=5353, Protocol=UDP
```

### DNS Queries
```
[DNS] ID=0x3f06, QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1, Query=www.google.com, Type=1, Class=1
```

## 🛠️ Building from Source

### Compilation Options

```bash
# Standard build
make

# Clean build artifacts
make clean

# Rebuild everything
make clean && make
```

### Build Configuration

The Makefile includes:
- **Compiler**: GCC with `-Wall` warnings
- **Libraries**: `libpcap` for packet capture
- **Include Paths**: `inc/` and `util/inc/`
- **Output**: Binary named `packet_parser`

## 🔧 Customization

### Adding New Protocol Support

1. Create header file in `inc/` directory
2. Implement parser in `src/` directory
3. Add routing logic in `packet_parser.c`
4. Update Makefile with new source files

### Modifying Output Format

Edit the logging calls in parser files to change output format:
```c
log_message("[CUSTOM] Your format here: %s\n", data);
```

## 🚨 Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Run with sudo
   sudo ./packet_parser eth0
   ```

2. **Interface Not Found**
   ```bash
   # List available interfaces
   ip link show
   # or
   ifconfig -a
   ```

3. **libpcap Not Found**
   ```bash
   # Install development package
   sudo apt-get install libpcap-dev
   ```

4. **Build Errors**
   ```bash
   # Clean and rebuild
   make clean && make
   ```

## 📝 License

This project is open source. 

## 👨‍💻 Author

**To Hoang Buu**

## 📚 References

- [libpcap Documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- [DNS RFC 1035](https://tools.ietf.org/html/rfc1035)
- [TCP/IP Protocol Suite](https://tools.ietf.org/html/rfc793)

---

**Note**: This tool is built for learning and research purposes.