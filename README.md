# DNP3 Attack and Detection Lab

**Practical DNP3 attack simulation and detection for security research and training purposes.**

## DISCLAIMER

This software is intended for **educational and authorized security testing purposes only**. Using this software against systems you do not own or without explicit permission is illegal and unethical. The authors are not responsible for any misuse or damage caused by this software.

**Use only in isolated lab environments or with explicit written authorization.**

## Overview

This repository contains DNP3 security testing tools developed for the [HardHat Security](https://hardhatsecurity.com) blog series on industrial protocol security. The tools simulate real-world DNP3 attack scenarios in a controlled environment for security research and training.

### Components

- **DNP3 PLC Simulator** - Vulnerable DNP3 outstation for testing
- **Attack-Capable HMI** - Terminal-based DNP3 master with security testing capabilities
- **Detection Queries** - Splunk queries for network-based attack detection

## Lab Setup

### Network Topology
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Windows Host  │    │   EWS Ubuntu    │    │   PLC Ubuntu    │
│  192.168.206.1  │    │ 192.168.206.101 │    │ 192.168.206.103 │
│                 │    │                 │    │                 │
│ • Splunk SIEM   │    │ • DNP3 HMI      │    │ • DNP3 Simulator│
│ • Wireshark     │    │ • Attack Tools  │    │ • Traffic Logs  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Prerequisites

**PLC Machine (Ubuntu):**
- Python 3.6+
- tcpdump
- Splunk Universal Forwarder (optional)

**EWS Machine (Ubuntu):**
- Python 3.6+
- Network access to PLC machine

**Monitoring Host (Windows):**
- Splunk Enterprise
- Wireshark/tshark
- Network visibility to both machines

## Installation

### PLC Setup (192.168.206.103)

1. **Clone repository:**
```bash
git clone https://github.com/your-org/dnp3-security-lab.git
cd dnp3-security-lab/plc
```

2. **Install dependencies:**
```bash
sudo apt update
sudo apt install python3 tcpdump
pip3 install -r requirements.txt
```

3. **Configure traffic logging:**
```bash
# Start packet capture for Splunk ingestion
sudo tcpdump -i any port 20000 -v > /var/log/dnp3_traffic.log &
```

4. **Run DNP3 simulator:**
```bash
python3 dnp3_plc_simulator.py
```

### HMI Setup (192.168.206.101)

1. **Navigate to HMI directory:**
```bash
cd dnp3-security-lab/hmi
```

2. **Install dependencies:**
```bash
pip3 install -r requirements.txt
```

3. **Run attack-capable HMI:**
```bash
python3 ubuntu_hmi.py
```

4. **Connect to PLC:**
```
HMI> 1  # Connect to 192.168.206.103:20000
```

## Attack Scenarios

### Supported Attack Vectors

| Attack | Command | Description | Risk Level |
|--------|---------|-------------|------------|
| **Unauthorized Write** | `HMI> 8 → a` | Send control commands without authentication | HIGH |
| **DoS Attack** | `HMI> 8 → c` | Flood PLC with 100 rapid requests | HIGH |
| **Cold Restart** | `HMI> 7` | Force unexpected system restart | CRITICAL |
| **Malformed Packets** | `HMI> 8 → b` | Send corrupted DNP3 frames | MEDIUM |
| **Invalid Functions** | `HMI> 8 → e` | Test unsupported function codes | MEDIUM |
| **Packet Flood** | `HMI> 8 → d` | Network-level packet flooding | HIGH |

### Example Usage

```bash
# Connect to PLC
HMI> 1
[+] Connected to PLC 192.168.206.103:20000

# Execute unauthorized write attack
HMI> 8
Attack> a
[!] ATTACK: Direct unauthorized write sent (func=2)

# Monitor PLC console for attack detection
[!] ATTACK_DETECTED: UNAUTHORIZED_WRITE from_ip=192.168.206.101 severity=HIGH
```

## Detection and Monitoring

### Splunk Integration

**Configure Universal Forwarder on PLC:**
```bash
# Add to inputs.conf
[monitor:///var/log/dnp3_traffic.log]
disabled = false
sourcetype = dnp3_network
index = main
```

**Deploy Detection Queries:**
```splunk
# Comprehensive attack detection
index=* sourcetype="dnp3_network"
| search "PLC.20000"
| eval attack_type=case(
    match(_raw, "length 23"), "Unauthorized Write",
    len(_raw) > 30000, "DoS Attack", 
    match(_raw, "length 13"), "Cold Restart",
    1=1, "Normal Traffic"
)
| where attack_type!="Normal Traffic"
```

### MITRE ATT&CK Mapping

Attack vectors map to MITRE ATT&CK ICS framework:
- **T0836** - Modify Parameter (Unauthorized Write)
- **T0814** - Denial of Service (DoS/Flood attacks)
- **T0816** - Device Restart/Shutdown (Cold Restart)

## Security Considerations

### Lab Isolation
- **Use isolated networks only** - Never deploy on production systems
- **VM environments recommended** - Easy to reset and contain
- **Network segmentation** - Prevent accidental exposure to corporate networks

### Responsible Disclosure
- Report vulnerabilities found in real systems through proper channels
- Follow coordinated vulnerability disclosure processes
- Respect intellectual property and licensing terms

## Contributing

We welcome contributions that enhance the educational value of this lab:

1. **New attack scenarios** - Additional DNP3 attack vectors
2. **Detection improvements** - Better Splunk queries and detection logic
3. **Documentation** - Setup guides and troubleshooting tips
4. **Integration guides** - Support for additional SIEM platforms

### Development Guidelines
- Maintain educational focus - Tools should teach security concepts
- Document all changes - Clear commit messages and update README
- Test thoroughly - Verify functionality across different environments
- Follow ethical guidelines - No tools designed for malicious use

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Support and Community

- **Blog Series:** [DNP3 Security Testing Guide](https://hardhatsecurity.com)
- **Issues:** Report bugs and request features via GitHub Issues
- **Discussions:** Join security research discussions in GitHub Discussions

## Authors

Created by the HardHatSecurity.com team for industrial cybersecurity education and research.

## Acknowledgments

- Industrial control system security research community
- MITRE ATT&CK ICS framework contributors
- Open-source DNP3 protocol implementations

---

**Remember: Use responsibly, test ethically, secure the grid.**
