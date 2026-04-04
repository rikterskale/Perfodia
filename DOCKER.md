# PentestFW — Docker Guide

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
docker build -t pentestfw .

# Check that all tools are installed
docker run --rm pentestfw --check-tools

# Scan a target on your lab network
docker run --rm --net=host pentestfw -t 192.168.1.100 -m scan -v

# Full pentest with reports saved to host
docker run --rm --net=host \
    -v "$(pwd)/reports:/opt/pentestfw/reports" \
    pentestfw -t 192.168.1.100 -m full -v
```

---

## Building the Image

### Full Image (Default)

Includes all tools: nmap, enum4linux-ng, impacket, hydra, nikto, gobuster, hashcat, john, searchsploit, responder, snmpwalk, and more.

```bash
docker build -t pentestfw .
# or explicitly:
docker build -t pentestfw:full --target full .
```

**Build time:** ~5-10 minutes (depends on network speed)
**Image size:** ~1.5-2 GB

### Minimal Image

Includes only: nmap, dig, whois, curl, snmpwalk, nbtscan. Enough for reconnaissance and network scanning.

```bash
docker build -t pentestfw:minimal --target minimal .
```

**Image size:** ~400-600 MB

### Build Options

```bash
# No cache (force fresh build)
docker build --no-cache -t pentestfw .

# Show full build output
docker build --progress=plain -t pentestfw .

# Build for a different architecture (e.g., on Apple Silicon for x86 lab)
docker build --platform linux/amd64 -t pentestfw .
```

---

## Running the Framework

### Basic Scans

```bash
# Recon only (DNS, WHOIS — no port scanning)
docker run --rm --net=host pentestfw -t target.lab.local -m recon -v

# Network scanning
docker run --rm --net=host pentestfw -t 192.168.1.0/24 -m scan -v

# Scan + enumeration
docker run --rm --net=host pentestfw -t 192.168.1.100 -m scan --enum -v

# Full pentest (all 5 phases)
docker run --rm --net=host pentestfw -t 192.168.1.100 -m full -v

# Dry run (shows commands without executing them)
docker run --rm --net=host pentestfw -t 192.168.1.100 -m full --dry-run -vv
```

### Saving Reports to Your Host

By default, reports stay inside the container and disappear when it exits. Mount a volume to persist them:

```bash
# Save to ./reports on your host
docker run --rm --net=host \
    -v "$(pwd)/reports:/opt/pentestfw/reports" \
    pentestfw -t 192.168.1.100 -m full -v

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
```

### Using Custom Configs

Mount your config file into the container:

```bash
# Edit configs/default.yaml on your host, then:
docker run --rm --net=host \
    -v "$(pwd)/configs:/opt/pentestfw/configs:ro" \
    -v "$(pwd)/reports:/opt/pentestfw/reports" \
    pentestfw -t 192.168.1.100 -m full -c /opt/pentestfw/configs/default.yaml -v
```

### Custom Nmap Options

All `--nmap-*` flags work exactly the same inside Docker:

```bash
# Add UDP scanning
docker run --rm --net=host pentestfw \
    -t 192.168.1.100 -m scan --nmap-extra '-sU -Pn' -v

# Replace default nmap flags entirely
docker run --rm --net=host pentestfw \
    -t 192.168.1.100 -m scan --nmap-raw '-sT -sV -p 22,80,443' -v

# Full connect scan (if you can't use --net=host)
docker run --rm pentestfw \
    -t 192.168.1.100 -m scan --nmap-scan-type sT -v

# Custom NSE scripts
docker run --rm --net=host pentestfw \
    -t 192.168.1.100 -m scan --nmap-scripts 'smb-vuln*' -v
```

### Interactive Shell

Drop into a bash shell inside the container to run tools manually:

```bash
docker run --rm -it --net=host \
    -v "$(pwd)/reports:/opt/pentestfw/reports" \
    pentestfw shell

# Now you're inside the container:
pentester@host:/opt/pentestfw$ nmap -sV 192.168.1.100
pentester@host:/opt/pentestfw$ sudo python3 pentestfw.py -t 192.168.1.100 -m scan -v
pentester@host:/opt/pentestfw$ enum4linux-ng 192.168.1.100
pentester@host:/opt/pentestfw$ searchsploit apache 2.4
```

### Running Tools Directly

Use individual tools without invoking the framework:

```bash
# Run nmap directly
docker run --rm --net=host pentestfw nmap -sV -p 80,443 192.168.1.100

# Run searchsploit
docker run --rm pentestfw searchsploit vsftpd 2.3

# Run hydra
docker run --rm --net=host pentestfw hydra -l admin -P /usr/share/wordlists/quick_passwords.txt ssh://192.168.1.100

# Run enum4linux-ng
docker run --rm --net=host pentestfw enum4linux-ng 192.168.1.100

# Run impacket-secretsdump
docker run --rm --net=host pentestfw impacket-secretsdump user:password@192.168.1.100
```

---

## Docker Compose

Docker Compose simplifies repeated runs:

```bash
# Build both images
docker compose build

# Run the full framework
docker compose run --rm pentestfw -t 192.168.1.100 -m full -v

# Run the minimal variant
docker compose run --rm pentestfw-minimal -t 192.168.1.100 -m scan -v

# Interactive shell
docker compose run --rm pentestfw shell

# Check tools
docker compose run --rm pentestfw check-tools

# Run a one-off nmap scan
docker compose run --rm pentestfw nmap -sV -sC -p- 192.168.1.100

# Tear down (removes containers, not images)
docker compose down
```

Reports are automatically saved to `./reports/` on your host via the volume mount defined in `docker-compose.yml`.

---

## Networking

### Host Networking (Recommended)

```bash
docker run --rm --net=host pentestfw -t 192.168.1.100 -m scan -v
```

`--net=host` gives the container direct access to your host's network interfaces. This is **required** for:
- SYN scans (`-sS`) — the default scan type
- OS fingerprinting (`-O`)
- Raw packet tools (masscan, responder)
- Scanning targets on your local LAN

### Bridge Networking

If you can't use `--net=host`, use the default bridge network with a full-connect scan:

```bash
docker run --rm pentestfw \
    -t 192.168.1.100 -m scan --nmap-scan-type sT -v
```

This works for scanning remote hosts that are routable from the Docker bridge, but:
- SYN scans won't work (use `--nmap-scan-type sT` instead)
- OS fingerprinting may be inaccurate
- You can't scan hosts on your host's LAN directly

### Scanning Docker Networks

To scan other Docker containers:

```bash
# Create a shared network
docker network create pentest-lab

# Start your target container(s) on that network
docker run -d --name target --network pentest-lab vulnerable-app

# Scan from pentestfw on the same network
docker run --rm --network pentest-lab pentestfw \
    -t target -m scan --nmap-scan-type sT -v
```

---

## Volumes & Persistence

| Host path | Container path | Purpose |
|-----------|---------------|---------|
| `./reports` | `/opt/pentestfw/reports` | Scan results, reports, logs |
| `./configs` | `/opt/pentestfw/configs` | Custom YAML configuration files |
| `./wordlists` | `/usr/share/wordlists` | Custom password/directory wordlists |

### Mounting Wordlists

The full image includes small built-in wordlists. To use your own (rockyou.txt, SecLists, etc.):

```bash
docker run --rm --net=host \
    -v "$(pwd)/reports:/opt/pentestfw/reports" \
    -v "/path/to/SecLists:/usr/share/wordlists/SecLists:ro" \
    -v "/path/to/rockyou.txt:/usr/share/wordlists/rockyou.txt:ro" \
    pentestfw -t 192.168.1.100 -m full -v
```

---

## Image Variants

| Variant | Target | Size | Tools included |
|---------|--------|------|---------------|
| `pentestfw:full` | `full` | ~1.5-2 GB | Everything: nmap, enum4linux-ng, impacket, hydra, nikto, gobuster, hashcat, john, searchsploit, responder, snmpwalk, smbclient, whatweb, dnsrecon, sqlmap |
| `pentestfw:minimal` | `minimal` | ~400-600 MB | Scanning only: nmap, dig, whois, curl, snmpwalk, nbtscan, traceroute |

---

## Security Considerations

**This image is a penetration testing tool.** Handle it responsibly:

- **Do not push to public registries** with credentials or sensitive configs baked in.
- **`--net=host`** gives the container full network access — it can see and interact with everything on your host's network.
- **`--privileged`** (not required by default) would give root-equivalent access to the host. Avoid unless specifically needed.
- **`cap_add: NET_ADMIN, NET_RAW`** (used in docker-compose.yml) is the minimum capability set needed for SYN scans and raw packet operations.
- The container runs as a non-root `pentester` user with passwordless sudo inside the container. This is a convenience for lab use — harden as needed for shared environments.
- **Reports may contain sensitive data** (credentials, hashes, network maps). Secure your `./reports` directory.

---

## Troubleshooting

### "No default route detected"

You're running without `--net=host`. Either add it or accept that some scan types won't work:

```bash
docker run --rm --net=host pentestfw -t 192.168.1.100 -m scan -v
```

### "SYN scan may not work"

SYN scans need raw socket access. Options:

```bash
# Option 1: Host networking (recommended)
docker run --rm --net=host pentestfw -t 192.168.1.100 -m scan -v

# Option 2: Add capabilities
docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW pentestfw \
    -t 192.168.1.100 -m scan -v

# Option 3: Use connect scan instead (no special privileges needed)
docker run --rm pentestfw -t 192.168.1.100 -m scan --nmap-scan-type sT -v
```

### "Tool X not found" in minimal image

The minimal image only includes core scanning tools. Switch to the full image:

```bash
docker build -t pentestfw:full --target full .
docker run --rm --net=host pentestfw:full -t 192.168.1.100 -m full -v
```

### Reports disappear after container exits

Mount a volume:

```bash
docker run --rm --net=host \
    -v "$(pwd)/reports:/opt/pentestfw/reports" \
    pentestfw -t 192.168.1.100 -m scan -v
```

### Container can't reach target on LAN

Make sure you're using `--net=host`:

```bash
# Verify from inside the container
docker run --rm -it --net=host pentestfw shell
pentester@host$ ping 192.168.1.100
pentester@host$ nmap -sn 192.168.1.0/24
```

### Image build fails on ARM (Apple Silicon Mac)

Force x86 emulation:

```bash
docker build --platform linux/amd64 -t pentestfw .
```

Performance will be slower under emulation. For best results, build and run on an x86_64 machine.

### Rebuilding after code changes

```bash
docker build --no-cache -t pentestfw .
# or just the layers that changed:
docker build -t pentestfw .
```
