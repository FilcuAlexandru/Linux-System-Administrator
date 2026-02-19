# System Crawler v0.0.1

**Linux Server System Information Aggregator**

A comprehensive Python-based system information gathering tool for Linux servers that executes 15 specialized crawlers to detect and report detailed information about OS, CPU, RAM, GPU, motherboard, USB, storage, network, PCI devices, sensors, audio, input devices, security, system services, and firmware using `/proc`, `/sys` filesystem interfaces and system commands.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Crawlers](#crawlers)
- [Examples](#examples)
- [Output Formats](#output-formats)
- [Dry-Run Mode](#dry-run-mode)
- [Safety Features](#safety-features)
- [Troubleshooting](#troubleshooting)
- [Performance](#performance)
- [Use Cases](#use-cases)
- [License](#license)

---

## Features

### Core Capabilities

- **15 Specialized Crawlers**
  - OS Information (kernel, distribution, architecture)
  - CPU Analysis (cores, model, frequency, virtualization)
  - Memory Analysis (capacity, usage, swap)
  - GPU Detection (NVIDIA, AMD, Intel, VMware)
  - Motherboard Information (manufacturer, BIOS, serial numbers)
  - USB Device Enumeration
  - Storage Hardware (disks, partitions, SMART status)
  - Network Configuration (interfaces, routing, DNS)
  - PCI Device Inventory
  - Sensor Information (temperature, voltage, fans)
  - Audio Devices (ALSA, PulseAudio, JACK)
  - Input Devices (keyboard, mouse, touchpad)
  - Security Configuration (SELinux, AppArmor, firewall)
  - System Services (systemd, daemons, timers)
  - BIOS/Firmware (UEFI, Secure Boot, TPM)

- **VMware & SUSE Linux Support**
  - VMware Tools detection
  - VMware-specific hardware (SVGA, ES1371)
  - SUSE Linux specific services and security
  - YaST2 configuration detection

- **Multiple Export Formats**
  - JSON (structured, machine-readable)
  - CSV (spreadsheet-compatible)
  - LOG (human-readable text)
  - HTML (web viewable with styling)

- **Safety Features**
  - Dry-run validation mode (default)
  - Crawler selection by name
  - Force flag requirement for 6+ crawlers
  - Resource consumption prevention

- **Operational Modes**
  - Dry-run simulation (check dependencies)
  - Full collection (gather data)
  - Selective crawler execution
  - Quiet mode (silent operation)

---

## Requirements

### Minimum Requirements

- **Python 3.6** or later
- **Linux kernel** 2.6+ with `/proc` filesystem
- **Basic utilities**: uname, cat, grep, awk

### Optional Tools (for enhanced detection)

For maximum hardware detection, optionally install:

```bash
# Debian/Ubuntu
sudo apt-get install util-linux lsb-release
sudo apt-get install lspci lsusb dmidecode smartmontools
sudo apt-get install hwinfo lm-sensors

# RHEL/CentOS
sudo yum install util-linux lsscsi
sudo yum install pciutils usbutils dmidecode smartmontools
sudo yum install lm_sensors

# SUSE Linux
sudo zypper install lsscsi pciutils usbutils dmidecode
sudo zypper install smartmontools lm_sensors
```

### Note

The script works with or without optional tools—it gracefully falls back to `/proc` and `/sys` when commands are unavailable.

---

## Installation

### 1. Clone or Download Repository

```bash
# Clone from repository
git clone https://github.com/yourusername/system_crawler.git
cd system_crawler

# Or download directly
wget https://example.com/system_crawler.zip
unzip system_crawler.zip
cd system_crawler
```

### 2. Create Directory Structure

```
system_crawler/
├── system_crawler.py          # Main aggregator script
└── crawlers/                  # Crawler modules directory
    ├── os_crawler.py
    ├── cpu_crawler.py
    ├── ram_crawler.py
    ├── gpu_crawler.py
    ├── motherboard_crawler.py
    ├── usb_crawler.py
    ├── storage_crawler.py
    ├── network_crawler.py
    ├── pci_crawler.py
    ├── sensors_crawler.py
    ├── audio_crawler.py
    ├── input_devices_crawler.py
    ├── security_crawler.py
    ├── system_services_crawler.py
    └── bios_crawler.py
```

### 3. Make Executable

```bash
chmod +x system_crawler.py
```

### 4. Verify Installation

```bash
python3.6 system_crawler.py --help
# Output: Shows help message with all available options
```

### 5. Run Validation

```bash
python3.6 system_crawler.py --dry-run=true
```

---

## Usage

### Quick Start

**Validate System Configuration (Dry-Run):**
```bash
python3.6 system_crawler.py
```

**Collect Specific Crawlers:**
```bash
python3.6 system_crawler.py --crawlers=os,cpu,ram --dry-run=false
```

**Collect All Crawlers (Requires --force):**
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
```

### Command Syntax

```bash
python3.6 system_crawler.py [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message with all options and examples |
| `--dry-run=true` | Validate dependencies (default) |
| `--dry-run=false` | Perform full collection |
| `--crawlers=name` | Specify crawlers (comma-separated) or "all" |
| `--force` | Force execution of 6+ crawlers (required safety flag) |

---

## Crawlers

### 1. OS Crawler

**Purpose:** Gather operating system and kernel information

**Detects:**
- OS distribution (Ubuntu, Debian, CentOS, SUSE, etc.)
- Kernel version and release
- Architecture (x86_64, ARM, etc.)
- Hostname, FQDN, domain
- System uptime
- Virtualization detection

**Command:**
```bash
python3.6 system_crawler.py --crawlers=os --dry-run=false
```

**Output Includes:**
- Kernel release version
- Distribution name and version
- Hardware architecture
- System hostname
- Kernel build info
- Virtualization type (KVM, VMware, Xen, etc.)

---

### 2. CPU Crawler

**Purpose:** Collect detailed CPU and processor information

**Detects:**
- CPU model and vendor
- Physical core count
- Logical thread count
- CPU frequency (current, min, max)
- Cache size (L1, L2, L3)
- Stepping, family, microcode
- Virtualization support (VT-x, AMD-V)
- CPU flags and features

**Command:**
```bash
python3.6 system_crawler.py --crawlers=cpu --dry-run=false
```

**Output Includes:**
- Processor name and model
- Number of cores and threads
- Base and boost frequencies
- Cache hierarchy
- Instruction set extensions (SSE, AVX, etc.)
- Hypervisor support capabilities

---

### 3. RAM Crawler

**Purpose:** Analyze memory configuration and usage

**Detects:**
- Total physical memory
- Available and free memory
- Memory usage percentage
- Swap space (total, used, free)
- Buffers and cached memory
- Memory modules (if DMI available)
- Memory speed and type

**Command:**
```bash
python3.6 system_crawler.py --crawlers=ram --dry-run=false
```

**Output Includes:**
- Total RAM capacity
- Current memory usage
- Swap configuration
- Memory allocation breakdown
- Memory module specifications
- Memory performance info

---

### 4. GPU Crawler

**Purpose:** Detect graphics and display adapters

**Detects:**
- NVIDIA GPUs (via nvidia-smi)
- AMD GPUs (via rocm-smi)
- Intel integrated graphics
- VMware virtual GPUs
- Generic VGA devices
- GPU driver information
- GPU memory and capabilities

**Command:**
```bash
python3.6 system_crawler.py --crawlers=gpu --dry-run=false
```

**Output Includes:**
- GPU count and model names
- GPU driver version
- GPU memory capacity
- Compute capability
- GPU utilization and temperature
- CUDA/ROCm availability

---

### 5. Motherboard Crawler

**Purpose:** Gather motherboard and system board information

**Detects:**
- System manufacturer and product name
- Motherboard vendor and model
- BIOS vendor, version, and date
- Chassis type and manufacturer
- Serial numbers and UUIDs
- IPMI and baseboard info

**Command:**
```bash
python3.6 system_crawler.py --crawlers=motherboard --dry-run=false
```

**Output Includes:**
- System board information
- BIOS/UEFI details
- Hardware manufacturer
- DMI system identifiers
- Chassis configuration

---

### 6. USB Crawler

**Purpose:** Enumerate USB devices and ports

**Detects:**
- USB device count and listing
- USB hub information
- USB storage devices
- USB device speed and version
- USB kernel modules
- USB sysfs information

**Command:**
```bash
python3.6 system_crawler.py --crawlers=usb --dry-run=false
```

**Output Includes:**
- Connected USB devices
- USB device vendors and IDs
- USB bus topology
- USB speed capabilities
- USB driver information

---

### 7. Storage Crawler

**Purpose:** Analyze disks, partitions, and storage configuration

**Detects:**
- Physical disk list (HDDs, SSDs)
- Partition information
- Disk usage and free space
- Inode usage
- Mount points and configuration
- SMART status (if available)
- LVM information
- RAID configuration
- Filesystem types

**Command:**
```bash
python3.6 system_crawler.py --crawlers=storage --dry-run=false
```

**Output Includes:**
- Disk device names and sizes
- Partition layout
- Mount points and options
- Disk I/O statistics
- SMART health status
- LVM volumes and groups
- RAID devices and status

---

### 8. Network Crawler

**Purpose:** Collect network configuration and status

**Detects:**
- Network interfaces (ethernet, WiFi, loopback)
- IP addresses (IPv4 and IPv6)
- MAC addresses
- Routing table
- Default gateway
- DNS configuration
- Network connections (established, listening)
- Firewall rules
- Network device drivers

**Command:**
```bash
python3.6 system_crawler.py --crawlers=network --dry-run=false
```

**Output Includes:**
- Interface configuration
- IP address assignments
- Network routes and gateways
- DNS servers
- Network statistics
- Firewall status
- Network services

---

### 9. PCI Crawler

**Purpose:** Enumerate PCI devices and PCIe topology

**Detects:**
- All PCI devices count and listing
- PCI device classes (network, storage, graphics, etc.)
- PCI vendor and device IDs
- PCI driver assignments
- PCIe generation and speed
- IOMMU support (Intel VT-d, AMD-Vi)
- PCI hotplug capability
- Device capabilities (MSI, PM)

**Command:**
```bash
python3.6 system_crawler.py --crawlers=pci --dry-run=false
```

**Output Includes:**
- PCI device enumeration
- Device classification
- Kernel driver binding
- PCIe specifications
- IOMMU configuration
- Device capabilities

---

### 10. Sensors Crawler

**Purpose:** Monitor system sensors and thermal information

**Detects:**
- CPU temperature
- Thermal zones
- Fan speeds and control
- Voltage readings
- Power consumption
- hwmon devices
- ACPI thermal information
- Sensor alerts and limits

**Command:**
```bash
python3.6 system_crawler.py --crawlers=sensors --dry-run=false
```

**Output Includes:**
- Temperature sensors
- Fan speeds and PWM values
- Voltage measurements
- Thermal zone status
- Sensor alarms and thresholds
- Hardware monitoring data

---

### 11. Audio Crawler

**Purpose:** Detect audio devices and audio subsystems

**Detects:**
- Audio devices (sound cards)
- ALSA device list
- PulseAudio status
- JACK audio server
- Audio kernel modules
- Audio drivers
- Recording and playback devices
- Audio codec information

**Command:**
```bash
python3.6 system_crawler.py --crawlers=audio --dry-run=false
```

**Output Includes:**
- Audio device inventory
- Audio subsystem status
- ALSA/PulseAudio configuration
- Audio codec details
- Recording capabilities
- Audio server status

---

### 12. Input Devices Crawler

**Purpose:** Enumerate input devices (keyboard, mouse, etc.)

**Detects:**
- Keyboard devices
- Mouse and pointing devices
- Touchpad information
- USB input devices
- HID (Human Interface Device) devices
- Input device capabilities
- Event handler information

**Command:**
```bash
python3.6 system_crawler.py --crawlers=input_devices --dry-run=false
```

**Output Includes:**
- Input device list
- Keyboard layout and repeat settings
- Mouse sensitivity and buttons
- Touchpad capabilities
- HID device enumeration
- Input event handlers

---

### 13. Security Crawler

**Purpose:** Assess security configuration and hardening

**Detects:**
- SELinux status and policies
- AppArmor status and profiles
- Firewall configuration (iptables, firewalld, UFW)
- SSH security settings
- Sudo access and configuration
- User accounts and privileges
- Password policy settings
- SSL certificates
- Audit status
- File integrity checkers (AIDE, Tripwire)
- Security updates availability
- SUSE Linux specific security

**Command:**
```bash
python3.6 system_crawler.py --crawlers=security --dry-run=false
```

**Output Includes:**
- SELinux/AppArmor policies
- Firewall rules and status
- SSH configuration security
- Sudo permissions
- User account listing
- Password policy settings
- SSL certificate information
- Security update status

---

### 14. System Services Crawler

**Purpose:** Monitor system services and daemons

**Detects:**
- Systemd version
- Active services list
- Enabled services (boot-time)
- Failed services
- Essential system services
- Systemd targets and boot target
- Systemd timers (cron-like)
- Systemd sockets
- Running daemon processes
- Service dependencies

**Command:**
```bash
python3.6 system_crawler.py --crawlers=system_services --dry-run=false
```

**Output Includes:**
- Services status enumeration
- Active/inactive service count
- Failed service listing
- Boot-enabled services
- Service dependencies
- System target information
- Timer and socket units

---

### 15. BIOS Crawler

**Purpose:** Gather firmware and BIOS information

**Detects:**
- BIOS/UEFI firmware type
- BIOS vendor and version
- BIOS release date
- UEFI boot information
- Secure Boot status
- TPM (Trusted Platform Module) info
- Boot order and boot devices
- Bootloader type (GRUB, etc.)
- Kernel boot parameters
- ACPI support and tables
- Firmware update availability

**Command:**
```bash
python3.6 system_crawler.py --crawlers=bios --dry-run=false
```

**Output Includes:**
- Firmware type (BIOS/UEFI)
- Firmware version and date
- Boot configuration
- Secure Boot settings
- TPM status
- EFI System Partition info
- Boot loader details
- Kernel boot parameters

---

## Examples

### Example 1: Validate System (Dry-Run)

```bash
python3.6 system_crawler.py
# Output: Checks all crawler dependencies
```

### Example 2: Collect Specific Crawlers

```bash
python3.6 system_crawler.py --crawlers=os,cpu,ram --dry-run=false
# Collects OS, CPU, and RAM information (no --force needed, only 3 crawlers)
```

### Example 3: Collect 5 Crawlers (Maximum without --force)

```bash
python3.6 system_crawler.py --crawlers=os,cpu,ram,gpu,motherboard --dry-run=false
# Collects 5 crawlers without requiring --force flag
```

### Example 4: Collect All Crawlers (Requires --force)

```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# Collects all 15 crawlers - REQUIRES --force flag
```

### Example 5: Collect 6+ Specific Crawlers (Requires --force)

```bash
python3.6 system_crawler.py --crawlers=os,cpu,ram,gpu,motherboard,usb --dry-run=false --force
# 6 crawlers requires --force for safety
```

### Example 6: System Documentation

```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# Generates 4 report files:
# - system_report.json (structured data)
# - system_report.log (human-readable)
# - system_report.csv (spreadsheet-compatible)
# - system_report.html (web viewable)
```

### Example 7: Hardware Inventory with CSV

```bash
python3.6 system_crawler.py --crawlers=motherboard,cpu,ram,storage --dry-run=false
# Creates system_report.csv for import into spreadsheet
```

### Example 8: Security Audit with JSON

```bash
python3.6 system_crawler.py --crawlers=security,bios --dry-run=false
# Creates system_report.json for API integration
```

---

## Output Formats

### JSON Format

**Filename:** `system_report.json`

**Advantages:** Machine-readable, structured data, API-friendly, programming language support

**Contains:**
- Metadata (timestamp, crawler count, execution time)
- System data from all executed crawlers
- Hierarchical structure for easy parsing

**Usage:**
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
cat system_report.json | jq .
```

---

### CSV Format

**Filename:** `system_report.csv`

**Advantages:** Spreadsheet-compatible, Excel/Sheets support, easy pivot tables

**Contains:**
- Crawler name, key, and value columns
- One row per data item
- Suitable for data analysis

**Usage:**
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# Open system_report.csv in Excel or LibreOffice Calc
```

---

### LOG Format

**Filename:** `system_report.log`

**Advantages:** Human-readable, formatted sections, easy to review

**Contains:**
- Clear section headers
- Formatted output
- Hierarchical indentation

**Usage:**
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
less system_report.log
```

---

### HTML Format

**Filename:** `system_report.html`

**Advantages:** Web viewable, styled tables, easy navigation

**Contains:**
- Professional styling
- Metadata section
- Table-based data presentation
- Open in any web browser

**Usage:**
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
firefox system_report.html
```

---

## Dry-Run Mode

### What It Validates

For each selected crawler:
1. **Module Import** - Python crawler class loads successfully
2. **Dependencies** - Required system commands exist
3. **System Interfaces** - `/proc` and `/sys` filesystems available
4. **Permissions** - User has sufficient access rights

### Example Output

```
[OK] All crawlers imported successfully!

╔══════════════════════════════════════════════════════════════════════════════╗
║                        EXECUTING SYSTEM CRAWLERS                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

[*] Running OS crawler...
[*] Gathering OS information...
    [+] /etc/os-release - OK
    [+] hostnamectl - OK
    ...
[+] OS crawler completed!

╔══════════════════════════════════════════════════════════════════════════════╗
║                              EXECUTION SUMMARY                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ All crawlers executed successfully!                                          ║
║ Total crawlers run: 3                                                        ║
║ Execution time: 1.23 seconds                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### When to Use

- Before running full collection on new systems
- To troubleshoot missing dependencies
- To verify crawler availability
- To estimate execution time

---

## Safety Features

### Crawler Limit Protection

- **1-5 crawlers:** Execute directly
- **6+ crawlers:** Require `--force` flag
- **All crawlers (15):** Require `--force` flag

This prevents accidental heavy resource consumption.

### Force Flag Usage

```bash
# This will be REJECTED (6 crawlers, no --force)
python3.6 system_crawler.py --crawlers=os,cpu,ram,gpu,motherboard,usb --dry-run=false
# Error: Running 6 crawlers requires --force flag

# This will EXECUTE (6 crawlers WITH --force)
python3.6 system_crawler.py --crawlers=os,cpu,ram,gpu,motherboard,usb --dry-run=false --force
```

---

## Troubleshooting

### Missing Hardware Information

**Problem:** Some crawlers report "N/A" for data

**Cause:** Required tools not installed

**Solution:**
```bash
# Run dry-run to check dependencies
python3.6 system_crawler.py --dry-run=true

# Install missing tools
sudo apt-get install lspci lsusb dmidecode smartmontools
```

---

### DMI Information Not Available

**Problem:** Motherboard and BIOS info missing

**Cause:** dmidecode requires root privileges

**Solution:**
```bash
sudo python3.6 system_crawler.py --crawlers=motherboard,bios --dry-run=false
```

---

### GPU Not Detected

**Problem:** GPU crawler shows no devices

**Cause:** nvidia-smi or rocm-smi not installed

**Solution:**
```bash
# For NVIDIA GPUs
sudo apt-get install nvidia-utils

# For AMD GPUs
sudo apt-get install rocm-utils
```

---

### SMART Status Missing

**Problem:** Storage crawler missing SMART info

**Cause:** smartctl not installed

**Solution:**
```bash
sudo apt-get install smartmontools
sudo python3.6 system_crawler.py --crawlers=storage --dry-run=false
```

---

### Permission Denied Errors

**Problem:** Access denied to `/sys` or `/proc`

**Cause:** Running as non-root user with restricted permissions

**Solution:**
```bash
# Run with elevated privileges
sudo python3.6 system_crawler.py --crawlers=all --dry-run=false --force
```

---

## Performance

Typical execution times:

| Mode | Crawlers | Time |
|------|----------|------|
| Dry-run | All | < 1s |
| Single crawler | 1 | < 1s |
| Basic (3-5) | 3-5 | 1-2s |
| Extended (6-10) | 6-10 | 2-3s |
| Full (all 15) | 15 | 3-5s |

---

## Use Cases

### 1. System Audit and Documentation

Create comprehensive documentation for compliance:

```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# Generates all reports for audit trail
```

### 2. Hardware Inventory Management

Build CSV inventory for asset tracking:

```bash
python3.6 system_crawler.py --crawlers=motherboard,cpu,ram,gpu,storage --dry-run=false
# Open system_report.csv in Excel
```

### 3. Security Assessment

Evaluate system hardening:

```bash
python3.6 system_crawler.py --crawlers=security,bios --dry-run=false
# Review system_report.json for security posture
```

### 4. Automated Monitoring

Collect data as scheduled job:

```bash
# Add to crontab
0 2 * * * python3.6 /path/to/system_crawler.py --crawlers=all --dry-run=false --force
```

### 5. Problem Diagnosis

Debug system issues with comprehensive data:

```bash
sudo python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# Analyze system_report.json for issues
```

---

## Compatibility

**Tested On:**
- ✓ Ubuntu 20.04 LTS
- ✓ Ubuntu 22.04 LTS
- ✓ Debian 11
- ✓ CentOS 7
- ✓ RHEL 8
- ✓ SUSE Linux 15
- ✓ Alpine Linux

**Requirements Met:**
- ✓ Python 3.6+
- ✓ Linux kernel 2.6+
- ✓ No external Python dependencies

---

## Security

### Root Access Requirements

Some data requires elevated privileges:
- DMI Information (motherboard)
- SMART Status (storage)
- Certain kernel interfaces
- Security policies (SELinux, AppArmor)

Safe usage:

```bash
# Use sudo only when necessary
sudo python3.6 system_crawler.py --crawlers=motherboard,security --dry-run=false
```

### File Permissions

Control exported data access:

```bash
mkdir -p ./reports
chmod 700 ./reports
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# Reports stored with restricted access
```

---

## License

**MIT License**

Copyright (c) 2026 Filcu Alexandru

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## Support

For help and documentation:

```bash
python3.6 system_crawler.py --help
# Shows command-line options
```

---

## Author

**Filcu Alexandru**

Version 0.0.1 - February 2026

---

## Changelog

### Version 0.0.1

- ✓ 15 specialized crawler modules
- ✓ VMware and SUSE Linux support
- ✓ Multiple export formats (JSON, CSV, LOG, HTML)
- ✓ Safety features (--force flag, crawler limits)
- ✓ Dry-run validation mode
- ✓ Comprehensive error handling
- ✓ No external Python dependencies
- ✓ Python 3.6+ compatible
- ✓ Professional output formatting
- ✓ Detailed documentation

---

**System Crawler v0.0.1** - Linux System Information Aggregator