# Perfodia — Docker Guide

Run the full penetration testing framework in Docker without installing anything on your host.

> **⚠️ FOR AUTHORIZED LAB USE ONLY.** Only test systems you own or have written permission to test.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Building the Image](#building-the-image)
  - [Full Image](#full-image-default)
  - [Minimal Image](#minimal-image)
- [Running the Framework](#running-the-framework)
  - [Basic Scans](#basic-scans)
  - [Saving Reports to Your Host](#saving-reports-to-your-host)
  - [Using Custom Configs](#using-custom-configs)
  - [Custom Nmap Options](#custom-nmap-options)
  - [Interactive Shell](#interactive-shell)
  - [Running Tools Directly](#running-tools-directly)
- [Docker Compose](#docker-compose)
- [Networking](#networking)
  - [Host Networking (Recommended)](#host-networking-recommended)
  - [Bridge Networking](#bridge-networking)
  - [Scanning Docker Networks](#scanning-docker-networks)
- [Volumes & Persistence](#volumes--persistence)
- [Image Variants](#image-variants)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Build the full image
docker build -t perfodia .

# Check that all tools are installed
docker run --rm perfodia --check-tools

# Scan a target on your lab network
docker run --rm --net=host perfodia -t 192.168.1.100 -m scan -v

# Full pentest with reports saved to host
docker run --rm --net=host \
    -v "$(pwd)/reports:/opt/perfodia/reports" \
    perfodia -t 192.168.1.100 -m full -v

Building the Image
Full Image (Default)
Includes all tools: nmap, enum4linux-ng, impacket, hydra, nikto, gobuster, hashcat, john, searchsploit, responder, snmpwalk, and more.
docker build -t perfodia .
# or explicitly:
docker build -t perfodia:full --target full .
Build time: ~5-10 minutes (depends on network speed)
Image size: ~1.5-2 GB
Minimal Image
Includes only: nmap, dig, whois, curl, snmpwalk, nbtscan. Enough for reconnaissance and network scanning.
docker build -t perfodia:minimal --target minimal .
Image size: ~400-600 MB
Build Options
# No cache (force fresh build)
docker build --no-cache -t perfodia .

# Show full build output
docker build --progress=plain -t perfodia .

# Build for a different architecture (e.g., on Apple Silicon for x86 lab)
docker build --platform linux/amd64 -t perfodia .

Running the Framework
Basic Scans
# Recon only (DNS, WHOIS — no port scanning)
docker run --rm --net=host perfodia -t target.lab.local -m recon -v

# Network scanning
docker run --rm --net=host perfodia -t 192.168.1.0/24 -m scan -v

# Scan + enumeration
docker run --rm --net=host perfodia -t 192.168.1.100 -m scan --enum -v

# Full pentest (all 5 phases)
docker run --rm --net=host perfodia -t 192.168.1.100 -m full -v

# Dry run (shows commands without executing them)
docker run --rm --net=host perfodia -t 192.168.1.100 -m full --dry-run -vv
Saving Reports to Your Host
By default, reports stay inside the container and disappear when it exits. Mount a volume to persist them:
# Save to ./reports on your host
docker run --rm --net=host \
    -v "$(pwd)/reports:/opt/perfodia/reports" \
    perfodia -t 192.168.1.100 -m full -v

# After the scan, your reports are in:
ls reports/
# 20250322_143000/
#   ├── report.html
#   ├── report.json
#   ├── report.md
#   ├── nmap/
#   ├── enum/
#   ├── logs/
#   └── ...
Using Custom Configs
Mount your config file into the container:
# Edit configs/default.yaml on your host, then:
docker run --rm --net=host \
    -v "$(pwd)/configs:/opt/perfodia/configs:ro" \
    -v "$(pwd)/reports:/opt/perfodia/reports" \
    perfodia -t 192.168.1.100 -m full -c /opt/perfodia/configs/default.yaml -v
Custom Nmap Options
All --nmap-* flags work exactly the same inside Docker:
# Add UDP scanning
docker run --rm --net=host perfodia \
    -t 192.168.1.100 -m scan --nmap-extra '-sU -Pn' -v

# Replace default nmap flags entirely
docker run --rm --net=host perfodia \
    -t 192.168.1.100 -m scan --nmap-raw '-sT -sV -p 22,80,443' -v

# Full connect scan (if you can't use --net=host)
docker run --rm perfodia \
    -t 192.168.1.100 -m scan --nmap-scan-type sT -v

# Custom NSE scripts
docker run --rm --net=host perfodia \
    -t 192.168.1.100 -m scan --nmap-scripts 'smb-vuln*' -v
Interactive Shell
Drop into a bash shell inside the container to run tools manually:
docker run --rm -it --net=host \
    -v "$(pwd)/reports:/opt/perfodia/reports" \
    perfodia shell

# Now you're inside the container:
pentester@host:/opt/perfodia$ nmap -sV 192.168.1.100
pentester@host:/opt/perfodia$ sudo python3 perfodia.py -t 192.168.1.100 -m scan -v
pentester@host:/opt/perfodia$ enum4linux-ng 192.168.1.100
pentester@host:/opt/perfodia$ searchsploit apache 2.4
Running Tools Directly
Use individual tools without invoking the framework:
# Run nmap directly
docker run --rm --net=host perfodia nmap -sV -p 80,443 192.168.1.100

# Run searchsploit
docker run --rm perfodia searchsploit vsftpd 2.3

# Run hydra
docker run --rm --net=host perfodia hydra -l admin -P /usr/share/wordlists/quick_passwords.txt ssh://192.168.1.100

# Run enum4linux-ng
docker run --rm --net=host perfodia enum4linux-ng 192.168.1.100

# Run impacket-secretsdump
docker run --rm --net=host perfodia impacket-secretsdump user:password@192.168.1.100

Docker Compose
Docker Compose simplifies repeated runs:
# Build both images
docker compose build

# Run the full framework
docker compose run --rm perfodia -t 192.168.1.100 -m full -v

# Run the minimal variant
docker compose run --rm perfodia-minimal -t 192.168.1.100 -m scan -v

# Interactive shell
docker compose run --rm perfodia shell

# Check tools
docker compose run --rm perfodia check-tools

# Run a one-off nmap scan
docker compose run --rm perfodia nmap -sV -sC -p- 192.168.1.100

# Tear down
docker compose down

Networking
Host Networking (Recommended)
docker run --rm --net=host perfodia ...
Gives the container direct access to the host network stack — required for most scanning/enumeration tools.
Bridge Networking
Use only if you cannot use --net=host. Add -p port mappings if needed.
Scanning Docker Networks
To scan containers on the same Docker network, use --net=bridge and the container IP.

Volumes & Persistence
All reports and session data are written to /opt/perfodia/reports inside the container.
Mount it to keep results on your host.

Image Variants

perfodia:latest / perfodia:full — complete toolset
perfodia:minimal — lightweight recon/scanning only


Security Considerations

Use --net=host only in isolated lab environments.
Never run against production systems without explicit authorization.
All tool executions are sandboxed inside the container.


Troubleshooting

“command not found” → rebuild the image (docker build -t perfodia .)
Permission denied → add your user to the docker group or use sudo
No reports after run → make sure you mounted the volume correctly
Image too large → use the minimal target

For more help open an issue on GitHub or run docker run --rm perfodia --help.