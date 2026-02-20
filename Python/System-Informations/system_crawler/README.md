# System Crawler v0.0.1

**Linux Server System Information Aggregator**

A comprehensive Python-based system information gathering tool for Linux servers that executes 15 specialized crawlers to detect and report detailed information about OS, CPU, RAM, GPU, motherboard, USB, storage, network, PCI devices, sensors, audio, input devices, security, system services, and firmware using `/proc`, `/sys` filesystem interfaces and system commands.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Directory Structure](#directory-structure)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Crawlers - Detailed Description](#crawlers---detailed-description)
8. [Export Formats](#export-formats)
9. [Examples](#examples)
10. [Safety Features](#safety-features)
11. [Performance](#performance)
12. [Troubleshooting](#troubleshooting)
13. [Use Cases](#use-cases)
14. [Compatibility](#compatibility)
15. [Security](#security)
16. [License](#license)
17. [Changelog](#changelog)

---

## Project Overview

System Crawler is a modular Python tool designed to collect comprehensive system information from Linux servers. It uses a master/detail architecture:

- **Main Script (system_crawler.py)** - Orchestrates crawlers and exporters
- **15 Crawler Modules** - Each gathers specific system information
- **4 Exporter Modules** - Export data in different formats

The tool is designed for system audits, hardware inventory, security assessments, and automated monitoring.

### Key Characteristics

- **Modular Design** - Each crawler is independent and reusable
- **No External Dependencies** - Pure Python with standard library only
- **Multiple Export Formats** - JSON, CSV, LOG, HTML
- **Safety First** - Dry-run mode by default, force flags for heavy operations
- **VMware & SUSE Support** - Specialized detection for these platforms

---

## Features

### Core Capabilities

#### 1. **15 Specialized Crawlers**
- OS Information - Kernel, distribution, architecture
- CPU Analysis - Cores, model, frequency, virtualization
- Memory Analysis - Capacity, usage, swap
- GPU Detection - NVIDIA, AMD, Intel, VMware
- Motherboard Information - Manufacturer, BIOS, serial numbers
- USB Device Enumeration - Connected devices, topology
- Storage Hardware - Disks, partitions, SMART status
- Network Configuration - Interfaces, routing, DNS
- PCI Device Inventory - All PCI/PCIe devices
- Sensor Information - Temperature, voltage, fans
- Audio Devices - ALSA, PulseAudio, JACK
- Input Devices - Keyboard, mouse, touchpad, HID
- Security Configuration - SELinux, AppArmor, firewall
- System Services - Systemd, daemons, timers
- BIOS/Firmware - UEFI, Secure Boot, TPM

#### 2. **Platform-Specific Support**
- **VMware** - VMware Tools, virtual GPU, ES1371 audio
- **SUSE Linux** - YaST2 config, SuSEfirewall2, SUSE services

#### 3. **Multiple Export Formats**
- **JSON** - Structured, API-friendly, metadata included
- **CSV** - Spreadsheet-compatible for data analysis
- **LOG** - Human-readable text with clear sections
- **HTML** - Professional web-viewable reports with styling

#### 4. **Safety Features**
- Dry-run validation mode (default behavior)
- Selective crawler execution by name
- Force flag requirement for 6+ crawlers
- Resource consumption prevention
- No data modification operations

#### 5. **Operational Modes**
- Dry-run simulation - Validates dependencies
- Full collection - Gathers actual data
- Selective execution - Run specific crawlers
- Silent operation - Quiet mode for scripting

---

## Directory Structure

```
system_crawler/
│
├── system_crawler.py           # Main orchestrator script
│   ├── Imports all crawlers
│   ├── Imports all exporters
│   ├── Handles command-line arguments
│   ├── Manages execution flow
│   └── Calls appropriate exporters
│
├── crawlers/                   # Specialized crawler modules
│   ├── os_crawler.py           # Operating system information
│   ├── cpu_crawler.py          # CPU and processor details
│   ├── ram_crawler.py          # Memory and swap analysis
│   ├── gpu_crawler.py          # GPU and graphics detection
│   ├── motherboard_crawler.py  # Motherboard and BIOS info
│   ├── usb_crawler.py          # USB devices and ports
│   ├── storage_crawler.py      # Disks, partitions, RAID
│   ├── network_crawler.py      # Network interfaces, routing
│   ├── pci_crawler.py          # PCI/PCIe device inventory
│   ├── sensors_crawler.py      # Temperature, voltage, fans
│   ├── audio_crawler.py        # Audio devices and systems
│   ├── input_devices_crawler.py# Keyboard, mouse, HID
│   ├── security_crawler.py     # SELinux, firewall, SSH
│   ├── system_services_crawler.py # Systemd services
│   └── bios_crawler.py         # BIOS/UEFI and firmware
│
├── exporters/                  # Data export modules
│   ├── base_exporter.py        # Base class for all exporters
│   ├── json_exporter.py        # JSON format export
│   ├── csv_exporter.py         # CSV format export
│   ├── log_exporter.py         # LOG/text format export
│   └── html_exporter.py        # HTML format export
│
└── README.md                   # This file

Total: 23 Python modules (1 main + 15 crawlers + 4 exporters)
```

### Directory Responsibilities

**Main Script (system_crawler.py)**
- Parses command-line arguments
- Instantiates selected crawlers
- Calls crawler.gather_all_info() for each
- Instantiates appropriate exporters
- Calls exporter.export() for each format
- Manages execution flow and error handling

**Crawlers Directory (crawlers/)**
- Each file contains one crawler class
- Implements gather_all_info() method
- Implements export_to_dict() method
- Queries /proc, /sys, and system commands
- Returns structured data (OrderedDict)

**Exporters Directory (exporters/)**
- Each file contains one exporter class
- Extends BaseExporter
- Implements export() method
- Formats data appropriately
- Writes to file or returns string

---

## Requirements

### Minimum Requirements

- **Python 3.6** or later
- **Linux kernel** 2.6+ with `/proc` filesystem
- **Basic utilities**: uname, cat, grep, awk

### Optional Tools (Enhanced Detection)

For maximum hardware detection, optionally install:

#### Debian/Ubuntu
```bash
sudo apt-get install util-linux lsb-release
sudo apt-get install lspci lsusb dmidecode smartmontools
sudo apt-get install hwinfo lm-sensors
```

#### RHEL/CentOS
```bash
sudo yum install util-linux lsscsi
sudo yum install pciutils usbutils dmidecode smartmontools
sudo yum install lm_sensors
```

#### SUSE Linux
```bash
sudo zypper install lsscsi pciutils usbutils dmidecode
sudo zypper install smartmontools lm_sensors
```

### Important Note

The tool gracefully falls back to `/proc` and `/sys` when optional commands are unavailable. All crawlers work without external tools, though with reduced information.

---

## Installation

### Step 1: Clone or Download

```bash
# Clone from repository
git clone https://github.com/yourusername/system_crawler.git
cd system_crawler

# OR download and extract
wget https://example.com/system_crawler.zip
unzip system_crawler.zip
cd system_crawler
```

### Step 2: Verify Directory Structure

```bash
# Check that directories exist
ls -la
# Should show: system_crawler.py, crawlers/, exporters/

ls -la crawlers/
# Should show: 15 crawler files

ls -la exporters/
# Should show: 5 exporter files (base + 4 formats)
```

### Step 3: Make Scripts Executable

```bash
chmod +x system_crawler.py
chmod +x crawlers/*.py
chmod +x exporters/*.py
```

### Step 4: Verify Installation

```bash
# Test help message
python3.6 system_crawler.py --help
# Should display available options

# Test dry-run
python3.6 system_crawler.py
# Should complete without errors
```

---

## Usage

### Quick Start

#### 1. Validate System (Dry-Run, Default)
```bash
python3.6 system_crawler.py
# No arguments needed - validates all crawlers
```

#### 2. Collect Specific Crawlers (No Force Needed)
```bash
python3.6 system_crawler.py --crawlers=os,cpu,ram --dry-run=false
# 3 crawlers = no --force needed
```

#### 3. Collect 5 Crawlers (Maximum Without Force)
```bash
python3.6 system_crawler.py --crawlers=os,cpu,ram,gpu,motherboard --dry-run=false
# 5 crawlers = maximum allowed without --force
```

#### 4. Collect All Crawlers (Requires Force)
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# 15 crawlers = REQUIRES --force flag
```

### Command Syntax

```bash
python3.6 system_crawler.py [OPTIONS]
```

### Available Options

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--help` | - | - | Show help message |
| `--dry-run` | true/false | true | Run in simulation or execution mode |
| `--crawlers` | names or "all" | all | Specify crawlers (comma-separated) |
| `--force` | flag | - | Required for 6+ crawlers |

### Examples

```bash
# Validate system
python3.6 system_crawler.py

# Specific crawlers
python3.6 system_crawler.py --crawlers=os,cpu --dry-run=false

# All crawlers with force
python3.6 system_crawler.py --crawlers=all --dry-run=false --force

# Multiple crawlers
python3.6 system_crawler.py --crawlers=motherboard,cpu,ram,storage,network --dry-run=false
```

---

## Crawlers - Detailed Description

### 1. OS Crawler (`os_crawler.py`)

**Purpose:** Gather operating system and kernel information

**What It Detects:**
- Linux distribution name and version
- Kernel version and release
- System architecture (x86_64, ARM, etc.)
- Hostname and FQDN
- System uptime and boot time
- Virtualization type (KVM, VMware, Xen, Hyper-V)
- Hardware platform information
- Locale and timezone settings
- System time synchronization status

**Data Sources:**
- `/etc/os-release` - Distribution info
- `/proc/version` - Kernel info
- `uname` command - Architecture and hostname
- `hostnamectl` - System hostname
- `uptime` command - System uptime
- `systemd-detect-virt` - Virtualization

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=os --dry-run=false
```

---

### 2. CPU Crawler (`cpu_crawler.py`)

**Purpose:** Collect detailed CPU and processor information

**What It Detects:**
- CPU model name and vendor
- Physical core count
- Logical thread count
- CPU frequency (current, minimum, maximum)
- CPU cache sizes (L1, L2, L3)
- CPU stepping and family information
- Microcode version
- Virtualization support (VT-x, AMD-V)
- CPU flags and features (SSE, AVX, AES, etc.)
- Hyperthreading status

**Data Sources:**
- `/proc/cpuinfo` - Primary CPU information
- `lscpu` command - Detailed CPU specs
- `/sys/devices/system/cpu/` - CPU topology

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=cpu --dry-run=false
```

---

### 3. RAM Crawler (`ram_crawler.py`)

**Purpose:** Analyze memory configuration and usage

**What It Detects:**
- Total physical memory
- Available and free memory
- Currently used memory
- Memory usage percentage
- Memory buffers
- Cached memory
- Swap space (total, used, free)
- Swap usage percentage
- Slab memory usage
- Page tables memory
- Memory module details (from DMI)
- Memory speed and type
- ECC support

**Data Sources:**
- `/proc/meminfo` - Primary memory info
- `/proc/sys/vm/` - Virtual memory settings
- `dmidecode` command - Memory modules (root required)

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=ram --dry-run=false
```

---

### 4. GPU Crawler (`gpu_crawler.py`)

**Purpose:** Detect graphics and display adapters

**What It Detects:**
- NVIDIA GPUs (model, memory, driver)
- AMD GPUs (model, memory, driver)
- Intel integrated graphics
- VMware virtual GPUs
- Generic VGA devices
- 3D graphics controllers
- GPU memory capacity
- GPU driver information
- CUDA/ROCm support
- GPU utilization and temperature

**Data Sources:**
- `nvidia-smi` command - NVIDIA GPUs
- `rocm-smi` command - AMD GPUs
- `lspci` command - All GPUs
- `/sys/class/drm/` - DRM devices
- Kernel modules - GPU driver info

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=gpu --dry-run=false
```

---

### 5. Motherboard Crawler (`motherboard_crawler.py`)

**Purpose:** Gather motherboard and system board information

**What It Detects:**
- System manufacturer and product name
- Motherboard vendor and model
- Motherboard serial number
- BIOS vendor and version
- BIOS release date
- BIOS manufacturer
- Chassis type (Desktop, Laptop, Server, etc.)
- Chassis manufacturer
- Chassis serial number
- System UUID
- Baseboard information
- IPMI details (if available)
- PCI device count
- Hardware platform

**Data Sources:**
- `dmidecode` command - DMI/SMBIOS data (root required)
- `/sys/class/dmi/` - DMI filesystem
- `hostnamectl` - Hardware info
- `lspci` - PCI device count

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=motherboard --dry-run=false
```

---

### 6. USB Crawler (`usb_crawler.py`)

**Purpose:** Enumerate USB devices and ports

**What It Detects:**
- Total USB device count
- USB hub count
- Connected USB devices list
- USB device vendors and product IDs
- USB device classes (storage, input, etc.)
- USB device speeds (1.5Mbps, 12Mbps, 480Mbps, etc.)
- USB bus topology
- USB storage devices
- USB TTY devices
- USB kernel modules
- USB driver information
- `/sys/bus/usb/` hierarchy

**Data Sources:**
- `lsusb` command - USB device list
- `/sys/bus/usb/` - USB sysfs
- `/proc/bus/usb/` - USB proc interface
- `dmesg` - USB messages

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=usb --dry-run=false
```

---

### 7. Storage Crawler (`storage_crawler.py`)

**Purpose:** Analyze disks, partitions, and storage configuration

**What It Detects:**
- Physical disk list (HDDs, SSDs, NVMe)
- Disk size and type detection
- Partition information and layout
- Mount points and options
- Disk usage statistics
- Inode usage statistics
- Filesystem types
- `/etc/fstab` configuration
- SMART status (if available)
- Disk I/O statistics
- LVM logical volumes
- LVM volume groups
- RAID configuration
- RAID status
- Disk device information

**Data Sources:**
- `lsblk` command - Block devices
- `fdisk` command - Partition info
- `df` command - Disk usage
- `smartctl` command - SMART status (root required)
- `pvs`, `lvs`, `vgs` - LVM info (root required)
- `mdadm` - RAID status (root required)
- `/proc/partitions` - Partition list
- `/etc/fstab` - Mount configuration

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=storage --dry-run=false
```

---

### 8. Network Crawler (`network_crawler.py`)

**Purpose:** Collect network configuration and status

**What It Detects:**
- Network interface list
- Interface status (UP/DOWN)
- IPv4 addresses
- IPv6 addresses
- MAC addresses
- Interface statistics (packets, errors, dropped)
- Default gateway
- Routing table
- DNS configuration
- Network connections (TCP, UDP)
- ARP table entries
- Network interface speed and duplex
- Network drivers
- Firewall status
- Network services (SSH, HTTP, etc.)
- Hostname and FQDN
- Connectivity test results

**Data Sources:**
- `ip` command - IP configuration
- `ifconfig` command - Interface info
- `route` command - Routing table
- `/etc/resolv.conf` - DNS config
- `netstat` or `ss` - Connections
- `arp` command - ARP table
- `/etc/network/` - Network config
- `firewall-cmd` or `ufw` - Firewall status
- `dmesg` - Network messages

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=network --dry-run=false
```

---

### 9. PCI Crawler (`pci_crawler.py`)

**Purpose:** Enumerate PCI devices and PCIe topology

**What It Detects:**
- Total PCI device count
- Complete PCI device list
- PCI device classification
- PCI vendor and device IDs
- PCI revision IDs
- Driver assignment for each device
- PCIe generation and speed
- PCIe lane count
- IOMMU support (Intel VT-d, AMD-Vi)
- PCI hotplug capability
- Device capabilities (MSI, PM, etc.)
- PCI slot information
- PCI bridge hierarchy
- ROM/BIOS information
- PCI error status

**Data Sources:**
- `lspci` command - PCI device list
- `/sys/bus/pci/` - PCI sysfs
- `/sys/kernel/iommu_groups/` - IOMMU info
- Kernel module info - Driver details

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=pci --dry-run=false
```

---

### 10. Sensors Crawler (`sensors_crawler.py`)

**Purpose:** Monitor system sensors and thermal information

**What It Detects:**
- CPU temperature
- Thermal zone information
- Fan speeds and PWM values
- Voltage readings
- Power consumption
- hwmon devices
- ACPI thermal information
- Sensor alerts and limits
- Sensor thresholds
- Critical temperature points
- VMware/virtualization specific sensors
- Kernel temperature drivers
- Sensor statistics

**Data Sources:**
- `lm-sensors` - Temperature and voltage
- `/sys/class/thermal/` - Thermal zones
- `/sys/class/hwmon/` - Hardware monitoring
- ACPI interfaces - Thermal data
- `dmesg` - Sensor messages
- `/proc/acpi/` - ACPI information

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=sensors --dry-run=false
```

---

### 11. Audio Crawler (`audio_crawler.py`)

**Purpose:** Detect audio devices and audio subsystems

**What It Detects:**
- Audio device count and list
- Audio device vendors and models
- ALSA device configuration
- Sound card information
- PulseAudio status and version
- JACK audio server info
- Audio kernel modules
- Audio driver information
- Recording devices
- Playback devices
- Audio codec information
- Audio configuration files
- Audio server status

**Data Sources:**
- `aplay` command - ALSA playback devices
- `arecord` command - ALSA recording devices
- `alsactl` - ALSA configuration
- `pactl` command - PulseAudio info
- `jackctl` - JACK server info
- `/sys/class/sound/` - Sound devices
- Kernel modules - Audio driver
- Configuration files - Audio config

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=audio --dry-run=false
```

---

### 12. Input Devices Crawler (`input_devices_crawler.py`)

**Purpose:** Enumerate input devices (keyboard, mouse, etc.)

**What It Detects:**
- Keyboard devices
- Mouse and pointing devices
- Touchpad/trackpad information
- USB input devices
- HID (Human Interface Device) devices
- Input device capabilities
- Keyboard layout and repeat settings
- Mouse button count and sensitivity
- Touchpad gestures
- Input event handlers
- /dev/input/* devices
- Input subsystem modules
- VMware input device info

**Data Sources:**
- `/dev/input/` - Input devices
- `/sys/class/input/` - Input sysfs
- `lsusb` - USB input devices
- HID subsystem - HID devices
- Kernel modules - Input drivers
- X11/Wayland config - Input config
- `dmesg` - Input messages

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=input_devices --dry-run=false
```

---

### 13. Security Crawler (`security_crawler.py`)

**Purpose:** Assess security configuration and hardening

**What It Detects:**
- SELinux status and policies
- AppArmor status and profiles
- Firewall status (firewalld, UFW, iptables)
- SSH configuration and hardening
- Sudo access and configuration
- User accounts and privileges
- Password policy settings
- SSL/TLS certificates
- Audit daemon status
- File integrity checker status
- Security updates availability
- SUSE Linux security settings
- Kernel security parameters
- Security kernel modules

**Data Sources:**
- `getenforce` - SELinux status
- `/etc/selinux/` - SELinux config
- `aa-status` - AppArmor status
- `firewall-cmd` - Firewall status
- `/etc/ssh/` - SSH configuration
- `/etc/sudoers` - Sudo config
- `/etc/passwd`, `/etc/shadow` - User info
- `/etc/pam.d/` - PAM configuration
- `/etc/login.defs` - Login policy
- `openssl` - Certificate info
- `auditctl` - Audit status
- Security tools - AIDE, Tripwire

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=security --dry-run=false
```

---

### 14. System Services Crawler (`system_services_crawler.py`)

**Purpose:** Monitor system services and daemons

**What It Detects:**
- Systemd version
- Active services (running)
- Inactive services
- Failed services
- Enabled services (boot-time)
- Disabled services
- Essential system services status
- Systemd targets (runlevel equivalents)
- Current boot target
- Systemd timers (cron-like tasks)
- Systemd sockets
- Systemd mount units
- Running daemon processes
- Service dependencies
- Service resource usage (memory, CPU)
- User services
- Service unit files
- System logs and journalctl info

**Data Sources:**
- `systemctl` command - Service status
- `systemd-analyze` - Service startup
- `/etc/systemd/` - Systemd config
- `journalctl` - System journal
- `/sys/fs/cgroup/` - Resource usage
- Kernel process list - Daemon info
- Service unit files - Dependencies

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=system_services --dry-run=false
```

---

### 15. BIOS Crawler (`bios_crawler.py`)

**Purpose:** Gather firmware and BIOS information

**What It Detects:**
- BIOS/UEFI firmware type
- BIOS vendor and version
- BIOS release date
- UEFI boot mode status
- UEFI System Partition (ESP) info
- Secure Boot status and keys
- TPM (Trusted Platform Module) info
- TPM version and status
- Boot order configuration
- Boot loader type (GRUB, LILO, etc.)
- Kernel boot parameters
- ACPI support and tables
- ACPI daemons and tools
- EFI variables
- Firmware update availability
- SUSE firmware configuration
- VMware firmware info

**Data Sources:**
- `dmidecode` - BIOS info (root required)
- `/sys/firmware/efi/` - EFI info
- `efibootmgr` - UEFI boot entries
- `bootctl` - Systemd-boot info
- `/proc/cmdline` - Kernel parameters
- `/sys/firmware/acpi/` - ACPI info
- `/etc/default/grub` - GRUB config
- `mokutil` - MOK keys
- `tpm2-tools` - TPM info
- `fwupdmgr` - Firmware updates

**Execution Command:**
```bash
python3.6 system_crawler.py --crawlers=bios --dry-run=false
```

---

## Export Formats

### JSON Format

**Filename:** `system_report.json`

**Purpose:** Machine-readable, structured data for APIs and programmatic access

**Contains:**
- Metadata section (timestamp, crawler count, execution time)
- System data from all executed crawlers
- Hierarchical structure for easy parsing

**Advantages:**
- Machine-readable and parseable
- API-friendly for integration
- Supports nesting and complex structures
- Can be imported into most programming languages

**Usage:**
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
cat system_report.json | jq .metadata
```

---

### CSV Format

**Filename:** `system_report.csv`

**Purpose:** Spreadsheet-compatible format for data analysis

**Contains:**
- Three columns: Crawler, Key, Value
- One row per data item
- Suitable for import into Excel/Sheets

**Advantages:**
- Spreadsheet application support
- Easy pivot table creation
- Suitable for data analysis
- Can be imported into databases

**Usage:**
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
open system_report.csv  # macOS
libreoffice system_report.csv  # Linux
```

---

### LOG Format

**Filename:** `system_report.log`

**Purpose:** Human-readable text format for easy review

**Contains:**
- Clear section headers
- Formatted output with indentation
- Crawler sections with data
- Execution metadata

**Advantages:**
- Human-readable and searchable
- Easy to review and audit
- Suitable for documentation
- Can be viewed in any text editor

**Usage:**
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
less system_report.log
grep "CPU" system_report.log
```

---

### HTML Format

**Filename:** `system_report.html`

**Purpose:** Professional web-viewable format with styling

**Contains:**
- Metadata section with styling
- CSS styling for professional appearance
- HTML tables for data presentation
- Responsive layout

**Advantages:**
- Web browser compatible
- Professional appearance
- Easy navigation
- Suitable for sharing and presentations

**Usage:**
```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
firefox system_report.html  # Linux
open system_report.html     # macOS
start system_report.html    # Windows
```

---

## Examples

### Example 1: Quick Validation (Dry-Run)

```bash
$ python3.6 system_crawler.py

[OK] All crawlers imported successfully!

╔══════════════════════════════════════════════════════════════════════════════╗
║                        EXECUTING SYSTEM CRAWLERS                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

[*] Running OS crawler...
[+] OS crawler completed!

[*] Running CPU crawler...
[+] CPU crawler completed!

... (all crawlers execute)

╔══════════════════════════════════════════════════════════════════════════════╗
║                              EXECUTION SUMMARY                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ All crawlers executed successfully!                                          ║
║ Total crawlers run: 15                                                       ║
║ Execution time: 2.34 seconds                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Example 2: Collect Specific Crawlers (No Force Needed)

```bash
python3.6 system_crawler.py --crawlers=os,cpu,ram --dry-run=false

# Generates:
# - system_report.json
# - system_report.log
# - system_report.csv
# - system_report.html
```

### Example 3: Collect Maximum Without Force (5 Crawlers)

```bash
python3.6 system_crawler.py --crawlers=os,cpu,ram,gpu,motherboard --dry-run=false

# 5 crawlers = maximum allowed without --force
# Generates all 4 report files
```

### Example 4: Collect All Crawlers (Requires Force)

```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force

# All 15 crawlers execute
# Generates all 4 report files
```

### Example 5: System Hardware Inventory

```bash
python3.6 system_crawler.py --crawlers=motherboard,cpu,ram,gpu,storage --dry-run=false

# Collect hardware info for inventory
# Import system_report.csv into Excel
```

### Example 6: Security Audit

```bash
python3.6 system_crawler.py --crawlers=security,bios --dry-run=false

# Security focused data collection
# system_report.json for programmatic analysis
```

### Example 7: Network Configuration Audit

```bash
python3.6 system_crawler.py --crawlers=network,security --dry-run=false

# Network and security data
# system_report.html for review
```

---

## Safety Features

### Crawler Limit Protection

The tool prevents accidental heavy resource usage:

- **1-5 crawlers:** Execute directly without restrictions
- **6+ crawlers:** Require `--force` flag for safety
- **All crawlers (15):** Require `--force` flag for safety

### Force Flag Usage

```bash
# This WILL BE REJECTED (6 crawlers without --force)
python3.6 system_crawler.py --crawlers=os,cpu,ram,gpu,motherboard,usb --dry-run=false
# Error: Running 6 crawlers requires --force flag (max 5 without --force)

# This WILL EXECUTE (6 crawlers WITH --force)
python3.6 system_crawler.py --crawlers=os,cpu,ram,gpu,motherboard,usb --dry-run=false --force
```

### Default Dry-Run Mode

By default, the tool runs in dry-run mode:

```bash
python3.6 system_crawler.py
# Equivalent to: python3.6 system_crawler.py --dry-run=true
# Only validates, doesn't gather data
```

---

## Performance

Typical execution times:

| Scenario | Crawlers | Time |
|----------|----------|------|
| Dry-run validation | All (15) | < 1 second |
| Single crawler | 1 | < 1 second |
| Basic setup | 3-5 | 1-2 seconds |
| Extended setup | 6-10 | 2-3 seconds |
| Complete system | All (15) | 3-5 seconds |

### Performance Notes

- OS crawler: ~100ms
- CPU crawler: ~150ms
- Storage crawler: ~200-500ms (depends on disk count)
- Network crawler: ~300ms
- All crawlers: ~3-5s total

Actual times vary based on:
- System configuration complexity
- Number of devices (USB, PCI, storage)
- Network interface count
- Available system resources

---

## Troubleshooting

### Issue: "N/A" Values in Output

**Cause:** Optional tools are not installed

**Solution:**
```bash
# Check what's available
python3.6 system_crawler.py

# Install missing tools
sudo apt-get install lspci lsusb dmidecode smartmontools lm-sensors
```

### Issue: BIOS/DMI Information Missing

**Cause:** dmidecode requires root privileges

**Solution:**
```bash
sudo python3.6 system_crawler.py --crawlers=motherboard,bios --dry-run=false
```

### Issue: GPU Not Detected

**Cause:** nvidia-smi or rocm-smi not installed

**Solution:**
```bash
# For NVIDIA GPUs
sudo apt-get install nvidia-utils

# For AMD GPUs
sudo apt-get install rocm-utils

# For Intel GPUs
sudo apt-get install intel-gpu-tools
```

### Issue: SMART Data Missing

**Cause:** smartmontools not installed

**Solution:**
```bash
sudo apt-get install smartmontools
sudo python3.6 system_crawler.py --crawlers=storage --dry-run=false
```

### Issue: Permission Denied Errors

**Cause:** Running as non-root with restricted /sys or /proc access

**Solution:**
```bash
# Run with elevated privileges
sudo python3.6 system_crawler.py --crawlers=all --dry-run=false --force
```

---

## Use Cases

### 1. System Documentation

Create comprehensive documentation for compliance and archival:

```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# Generates all 4 report formats for documentation
```

### 2. Hardware Inventory

Build hardware inventory for asset management:

```bash
python3.6 system_crawler.py --crawlers=motherboard,cpu,ram,gpu,storage --dry-run=false
# Import system_report.csv into inventory database
```

### 3. Security Assessment

Evaluate security configuration and hardening:

```bash
python3.6 system_crawler.py --crawlers=security,bios --dry-run=false
# Analyze system_report.json for security posture
```

### 4. Automated Monitoring

Collect data as scheduled job for trend analysis:

```bash
# Add to crontab
0 2 * * * python3.6 /path/to/system_crawler.py --crawlers=all --dry-run=false --force
# Generates timestamped reports for comparison
```

### 5. Problem Diagnosis

Debug system issues with comprehensive data collection:

```bash
sudo python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# Analyze system_report.log or .json for anomalies
```

### 6. Pre-Migration Documentation

Document system before migration to new platform:

```bash
python3.6 system_crawler.py --crawlers=all --dry-run=false --force
# Create baseline for comparison post-migration
```

---

## Compatibility

**Tested and Verified On:**
- ✓ Ubuntu 20.04 LTS
- ✓ Ubuntu 22.04 LTS
- ✓ Debian 11
- ✓ CentOS 7
- ✓ RHEL 8
- ✓ SUSE Linux 15 SP7
- ✓ Alpine Linux

**Requirements Met:**
- ✓ Python 3.6+
- ✓ Linux kernel 2.6+
- ✓ No external Python dependencies

---

## Security

### Root Access Requirements

Some operations require elevated privileges:
- DMI Information (motherboard, BIOS)
- SMART Status (storage health)
- Certain kernel interfaces
- Security policy queries (SELinux, AppArmor)
- Firewall rule enumeration

### Safe Usage

```bash
# Use sudo only when necessary
sudo python3.6 system_crawler.py --crawlers=motherboard,security --dry-run=false

# Otherwise, run as regular user
python3.6 system_crawler.py --crawlers=os,cpu,ram --dry-run=false
```

### File Permissions

Control exported report access:

```bash
# Create restricted directory
mkdir -p ./reports
chmod 700 ./reports

# Run with output redirection
cd ./reports
python3.6 ../system_crawler.py --crawlers=all --dry-run=false --force
# Reports stored with restricted permissions
```

### Data Privacy

Reports contain system information that may be sensitive:
- Hostname and IP addresses
- Hardware serial numbers
- Disk partition layout
- Service configuration

Store reports securely and limit access appropriately.

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
# Shows all available options and examples
```

---

## Author

**Filcu Alexandru**

Version 0.0.1 - February 2026

---

## Changelog

### Version 0.0.1 (February 2026)

**Initial Release**

- ✓ 15 specialized crawler modules for comprehensive system information
- ✓ Modular architecture with separate crawlers and exporters
- ✓ VMware Tools and SUSE Linux specific detection
- ✓ Multiple export formats (JSON, CSV, LOG, HTML)
- ✓ Safety features (--force flag, crawler limits, dry-run mode)
- ✓ Dry-run validation mode for dependency checking
- ✓ Comprehensive error handling and graceful fallbacks
- ✓ No external Python dependencies (uses standard library only)
- ✓ Python 3.6+ compatible
- ✓ Professional output formatting with box drawing characters
- ✓ Detailed documentation and usage examples
- ✓ Support for 6+ major Linux distributions

---

**System Crawler v0.0.1** - Linux System Information Aggregator