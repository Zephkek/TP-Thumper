
# TP-Link VN020 DHCP Memory Corruption
## Technical Analysis of Firmware Vulnerability

### Overview
Critical memory corruption vulnerability discovered in TP-Link VN020 F3v(T) routers (firmware version TT_V6.2.1021) through malformed DHCP DISCOVER packets. Affects all TP-Link VN020-F3v(T) routers deployed by Tunisie Telecom and Topnet, the same issue has been identified in Algerian and Morocco versions, testing has been done on the Tunisian ones.
> **Note:** Since the firmware is proprietary, end-users cannot update it directly. Any patches must be deployed by ISPs, such as Tunisie Telecom, which distribute this router model.

### Vulnerability Details
- **Type**: Stack Buffer Overflow / Memory Corruption
- **Attack Vector**: DHCP DISCOVER Packet
- **Authentication**: None Required
- **Port**: UDP/67 (DHCP Server)
- **Impact**: DoS / Possible RCE

### Technical Analysis

#### Attack Vector Analysis
1. **Primary Stack Overflow**
   - Hostname buffer allocated: 64 bytes
   - POC sends: 127 bytes
   - Stack layout corruption:
```c
[buffer:64][saved EBP:4][RET:4]
```

2. **Vendor Option Parser State Confusion**
```c
// Triggers parser state machine bug
vendor_specific[] = { 
    0x00, 0x14, 0x22,  // TP-Link prefix
    0xFF, 0xFF, 0xFF   // Causes length validation bypass
};
```

3. **Length Field Exploitation**
```c
// Router assumes full length during parsing
add_option(packet, offset, 0x3D, 0xFF, {0x01});
// Claims 255 bytes but only sends 1
```

### Proof of Concept
#### Video Demonstration

https://github.com/user-attachments/assets/ed897aed-540e-4ad8-8f70-788b264036bd


https://github.com/user-attachments/assets/46c6a5f0-c693-4a68-acbb-058fd1113fb6

Router may also try to restart it self as shown here due to the crash as shown here: 

https://github.com/user-attachments/assets/0e2d2905-74ac-4829-b127-538f2d159d0d




Key exploitation primitives:

```c
void create_exploit_packet() {
    // 1. Craft oversized hostname
    char overflow[128];
    memset(overflow, 'A', 127);
    
    // 2. Add malformed vendor option
    char vendor[] = {0x00,0x14,0x22,0xFF,0xFF};
    
    // 3. Trigger length field bug
    char invalid_len = 0xFF;
}
```

### Root Cause
1. Missing bounds checking in hostname parsing
2. Improper validation of option lengths
3. Parser state confusion in vendor-specific options

### Timeline
- Discovery: 10/20/2024
- Reported: 11/3/2024
- Fixed: Pending

### Researcher
Mohamed Maatallah
(https://github.com/Zephkek)

### References
- TP-Link VN020 Firmware Analysis
- [CVE ID Pending]

---
