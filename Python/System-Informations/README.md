# Hardware Crawler v0.0.1

**Linux Server Hardware Detection Tool**

A comprehensive Python-based hardware information gathering tool for Linux servers that detects and reports detailed information about CPU, RAM, motherboard, storage devices, GPUs, and other hardware components using `/proc`, `/sys` filesystem interfaces and system commands.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Verbosity Levels](#verbosity-levels)
- [Output Formats](#output-formats)
- [Dry-Run Mode](#dry-run-mode)
- [Hardware Detection Methods](#hardware-detection-methods)
- [Troubleshooting](#troubleshooting)
- [Performance](#performance)
- [Use Cases](#use-cases)
- [License](#license)

---

## Features

### Core Capabilities

- **Multi-layer Hardware Detection**
  - `/proc` filesystem interface
  - `/sys` sysfs interface
  - System commands (lscpu, lsblk, lspci, etc.)

- **Comprehensive Hardware Coverage**
  - Operating System (kernel, distribution, architecture)
  - CPU Components (cores, model, frequency, virtualization, flags)
  - Memory Analysis (capacity, modules, speed, ECC, timings)
  - Motherboard Information (manufacturer, BIOS, serial numbers)
  - Storage Hardware (HDDs/SSDs, types, SMART status)
  - GPU Devices (VGA and 3D graphics controllers)
  - PCI Device Inventory
  - USB Device Enumeration

- **Flexible Verbosity Levels**
  - `--v` (Basic): Essential information only
  - `--vv` (Extended): Detailed specifications
  - `--vvv` (Deep): Complete hardware enumeration

- **Multiple Export Formats**
  - JSON (structured, machine-readable)
  - CSV (spreadsheet-compatible)
  - LOG (human-readable text)

- **Operational Modes**
  - Dry-run validation (check dependencies)
  - Full collection (gather data)
  - Debug mode (troubleshooting)
  - Quiet mode (silent operation)

---

## Requirements

### Minimum Requirements

- **Python 3.6** or later
- **Linux kernel** 2.6+ with `/proc/cpuinfo`
- **Basic utilities**: uname, cat, grep

### Optional Tools (for enhanced detection)

For maximum hardware detection, optionally install:

```bash
# Debian/Ubuntu
sudo apt-get install util-linux hwinfo lsb-release
sudo apt-get install lspci lsusb dmidecode smartmontools

# RHEL/CentOS
sudo yum install util-linux lsscsi
sudo yum install pciutils usbutils dmidecode smartmontools
```

### Note

The script works with or without optional tools—it gracefully falls back to `/proc` and `/sys` when commands are unavailable.

---

## Installation

### 1. Download Script

```bash
# Download the script
wget https://example.com/hardware_crawler.sh
# or
curl -O https://example.com/hardware_crawler.sh
```

### 2. Make Executable

```bash
chmod +x hardware_crawler.sh
```

### 3. Verify Installation

```bash
./hardware_crawler.sh --version
# Output: hardware_crawler version 2.0.0
```

### 4. Run Validation

```bash
./hardware_crawler.sh --dry-run=true
```

---

## Usage

### Quick Start

**Validate System Configuration:**
```bash
./hardware_crawler.sh --dry-run=true
```

**Collect Basic Hardware Info:**
```bash
./hardware_crawler.sh --dry-run=false --v
```

**Collect Extended Details:**
```bash
./hardware_crawler.sh --dry-run=false --vv
```

**Collect Everything:**
```bash
./hardware_crawler.sh --dry-run=false --vvv
```

### Command Syntax

```bash
python3 hardware_crawler.sh [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message with 10 detailed examples |
| `--version` | Show version information |
| `--debug` | Enable debug logging to stderr |
| `--quiet` | Suppress console output (except exports) |
| `--dry-run=true` | Validate dependencies (default) |
| `--dry-run=false` | Perform full collection |
| `--v` | Basic information (4-7 fields per component) |
| `--vv` | Extended information (9-15 fields per component) |
| `--vvv` | Deep enumeration (15+ fields per component) |
| `--export=json` | Export to JSON format |
| `--export=csv` | Export to CSV format |
| `--export=log` | Export to LOG format |
| `--export-directory=/path` | Custom export directory |

---

## Examples

For comprehensive examples, run:

```bash
./hardware_crawler.sh --help
```

This shows 10 complete examples:

1. **VALIDATE SYSTEM CONFIGURATION** - Dry-run mode with dependency checks
2. **COLLECT BASIC HARDWARE** - Quick overview with --v
3. **COLLECT EXTENDED DETAILS** - Detailed specs with --vv
4. **COLLECT COMPLETE ENUMERATION** - Everything with --vvv
5. **EXPORT TO JSON** - Structured data format
6. **EXPORT TO CSV** - Spreadsheet compatible format
7. **EXPORT TO LOG** - Human-readable format
8. **DEBUG MODE** - Troubleshooting with full details
9. **QUIET MODE** - Silent operation with export
10. **COMPLETE DOCUMENTATION** - Full archival run

### Common Usage Patterns

**System Documentation:**
```bash
./hardware_crawler.sh --dry-run=false --vvv --export=log --export-directory=./docs
```

**Hardware Inventory:**
```bash
./hardware_crawler.sh --dry-run=false --vv --export=csv --export-directory=./inventory
```

**Compliance Auditing:**
```bash
sudo ./hardware_crawler.sh --dry-run=false --vvv --export=json
```

**Automated Monitoring:**
```bash
./hardware_crawler.sh --quiet --dry-run=false --vv --export=json --export-directory=/var/log/hardware
```

**Problem Diagnostics:**
```bash
./hardware_crawler.sh --debug --dry-run=false --vvv 2>&1 | tee diagnostic.log
```

---

## Verbosity Levels

### --v (BASIC)

**Fields:** 4-7 per component

**Includes:**
- OS: Kernel release, architecture, distribution
- CPU: Physical count, model, cores, vendor
- RAM: Total, swap, used
- Motherboard: Manufacturer, product name
- Storage: Device names, sizes, types
- GPU: Detection only

**Speed:** < 1 second

**Best For:** Quick checks, automated systems

---

### --vv (EXTENDED)

**Fields:** 9-15 per component

**Additional to --v:**
- OS: Kernel version, hardware platform
- CPU: Stepping, family, cache, frequency, virtualization
- RAM: Available, free, cached, buffered, DMI specs
- Motherboard: BIOS info, chassis type
- PCI: Device listing

**Speed:** 1-2 seconds

**Best For:** System audits, capacity planning

---

### --vvv (DEEP)

**Fields:** 15+ per component

**Additional to --vv:**
- OS: Build ID, version codename
- CPU: All flags, microcode, FPU details
- RAM: Active, inactive, dirty, huge pages, all DMI fields
- Motherboard: Serial numbers, UUID, SKU
- Storage: SMART status
- USB: Device enumeration

**Speed:** 2-5 seconds

**Best For:** Full documentation, compliance

---

## Output Formats

### JSON Format

**Filename:** `hardware_YYYYMMDD_HHMMSS.json`

**Advantages:** Machine-readable, structured data, API-friendly

```bash
./hardware_crawler.sh --dry-run=false --vv --export=json
```

---

### CSV Format

**Filename:** `hardware_YYYYMMDD_HHMMSS.csv`

**Advantages:** Spreadsheet-compatible, Excel/Sheets support

```bash
./hardware_crawler.sh --dry-run=false --vv --export=csv
```

---

### LOG Format

**Filename:** `hardware_YYYYMMDD_HHMMSS.log`

**Advantages:** Human-readable, formatted sections

```bash
./hardware_crawler.sh --dry-run=false --vv --export=log
```

---

## Dry-Run Mode

### What It Checks

For each hardware component:
1. **`/proc` Interface** - Kernel virtual filesystem
2. **`/sys` Interface** - Sysfs filesystem
3. **System Commands** - lscpu, lsblk, lspci, lsusb, dmidecode, smartctl

### Example Output

```
[INFO] Now checking dependencies and requirements for gathering the OS Informations ...
[INFO] Verifying the following dependencies and requirements:
[INFO]   └─ ✓ /proc/version
[INFO]   └─ ✓ /sys/kernel/
[INFO]   └─ ✓ uname
[INFO] Finalizing the validation of dependencies and requirements.
[INFO] The scripts can successfully gather the necessary OS Informations .

[INFO] The summary of the verification is available in the following overview:

+---------------------------+------------+--------+--------+--------+
|           CHECK           |   STATUS   |  --v   |  --vv  | --vvv  |
+---------------------------+------------+--------+--------+--------+
|      OS Informations      |     ✓      |   ✓    |   ✓    |   ✓    |
|     CPU Informations      |     ✓      |   ✓    |   ✓    |   ✓    |
...
```

### When to Use

- Before running full collection on new systems
- To troubleshoot missing hardware detection
- To verify all dependencies are installed
- To understand system capabilities

---

## Hardware Detection Methods

### Three-Layer Approach

**Layer 1: `/proc` Filesystem**
- CPU info, memory, devices, fast access

**Layer 2: `/sys` Sysfs**
- Modern kernel interface, structured hierarchy

**Layer 3: System Commands**
- Human-friendly output, extended capabilities

This ensures maximum compatibility across different Linux systems and kernel versions.

---

## Troubleshooting

### Missing Hardware Information

**Cause:** Required tools not installed

**Solution:**
```bash
# Check what's missing
./hardware_crawler.sh --dry-run=true

# Install required tools
sudo apt-get install lspci lsusb dmidecode smartmontools
```

---

### DMI Information Not Available

**Cause:** dmidecode requires root privileges

**Solution:**
```bash
sudo ./hardware_crawler.sh --dry-run=false --vvv
```

---

### SMART Status Not Showing

**Cause:** smartctl not installed

**Solution:**
```bash
sudo apt-get install smartmontools
sudo ./hardware_crawler.sh --dry-run=false --vvv
```

---

### USB Devices Not Detected

**Cause:** lsusb not installed

**Solution:**
```bash
sudo apt-get install usbutils
```

---

## Performance

Typical execution times:

| Mode | Time |
|------|------|
| `--dry-run=true` | < 1s |
| `--v` | < 1s |
| `--vv` | 1-2s |
| `--vvv` | 2-5s |

---

## Use Cases

### 1. System Documentation

Create comprehensive hardware documentation:
```bash
./hardware_crawler.sh --dry-run=false --vvv --export=log --export-directory=./docs
```

### 2. Hardware Inventory

Build CSV-based inventory:
```bash
./hardware_crawler.sh --dry-run=false --vv --export=csv --export-directory=./inventory
```

### 3. Compliance Auditing

Export complete data for audits:
```bash
sudo ./hardware_crawler.sh --dry-run=false --vvv --export=json
```

### 4. Automated Monitoring

Collect data as cron job:
```bash
0 2 * * * /path/to/hardware_crawler.sh --quiet --dry-run=false --vv --export=json --export-directory=/var/log/hardware
```

### 5. Problem Diagnostics

Debug with detailed logging:
```bash
./hardware_crawler.sh --debug --dry-run=false --vvv 2>&1 | tee diagnostic.log
```

---

## Compatibility

**Tested On:**
- Ubuntu 20.04 LTS
- Ubuntu 22.04 LTS
- Debian 11
- CentOS 7
- RHEL 8
- Alpine Linux
- SLES 15 SP7

**Requirements Met:**
- ✓ Python 3.6+
- ✓ Linux kernel 2.6+
- ✓ No external Python dependencies

---

## Security

### Root Access

Some data requires root privileges:
- DMI Information
- SMART Status
- Certain kernel interfaces

Safe usage:
```bash
# Use sudo only when needed
sudo ./hardware_crawler.sh --dry-run=false --vvv
```

### File Permissions

Control export access:
```bash
mkdir -p /var/log/hardware
chmod 700 /var/log/hardware
```

---

## License

**MIT License**

MIT License

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
./hardware_crawler.sh --help
./hardware_crawler.sh --version
./hardware_crawler.sh --dry-run=true
```

---

## Author

**Filcu Alexandru**

Version 0.0.1 - February 2025

---

## Changelog

### Version 0.0.1

- ✓ Multi-layer hardware detection (/proc, /sys, commands)
- ✓ Three verbosity levels (--v, --vv, --vvv)
- ✓ Multiple export formats (JSON, CSV, LOG)
- ✓ Dry-run validation mode
- ✓ Debug and quiet modes
- ✓ Professional output formatting
- ✓ Comprehensive error handling
- ✓ No external dependencies
- ✓ Python 3.6+ compatible
- ✓ 10 detailed usage examples

---

**Hardware Crawler v0.0.1** - Linux Hardware Detection Tool
