#!/usr/bin/env bash
###############################################################################
# Perfodia Docker Entrypoint
###############################################################################
# Handles:
#   - Running the framework with proper arguments
#   - Passing through raw tool commands
#   - First-run environment guidance for rootless Docker execution
###############################################################################

set -euo pipefail

FRAMEWORK="/opt/perfodia/perfodia.py"

RED='[0;31m'
GREEN='[0;32m'
YELLOW='[1;33m'
CYAN='[0;36m'
NC='[0m'

log()  { echo -e "${GREEN}[perfodia]${NC} $*"; }
warn() { echo -e "${YELLOW}[perfodia]${NC} $*"; }
err()  { echo -e "${RED}[perfodia]${NC} $*" >&2; }

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ] || [ $# -eq 0 ]; then
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  perfodia — Network Penetration Testing Framework      ║${NC}"
    echo -e "${CYAN}║  Docker Edition                                         ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Usage:"
    echo "  docker run --rm --net=host perfodia -t <target> -m <mode> [options]"
    echo ""
    echo "Quick examples:"
    echo "  docker run --rm perfodia --check-tools"
    echo "  docker run --rm --net=host perfodia -t 192.168.1.100 -m scan -v"
    echo "  docker run --rm perfodia -t 192.168.1.100 -m scan --nmap-scan-type sT -v"
    echo "  docker run --rm --net=host -v ./reports:/opt/perfodia/reports perfodia -t 192.168.1.0/24 -m full -v"
    echo "  docker run --rm -it --net=host perfodia shell"
    echo ""

    if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
        echo "─── Framework Help ───────────────────────────────────────────"
        python3 "$FRAMEWORK" --help
    fi
    exit 0
fi

if [ "$1" = "shell" ] || [ "$1" = "bash" ] || [ "$1" = "sh" ]; then
    log "Dropping into interactive shell..."
    exec /bin/bash
fi

if [ "$1" = "check" ] || [ "$1" = "check-tools" ]; then
    exec python3 "$FRAMEWORK" --check-tools
fi

DIRECT_TOOLS="nmap masscan nikto gobuster hydra snmpwalk whatweb searchsploit     smbclient rpcclient dig whois john hashcat sqlmap dnsrecon nbtscan curl     enum4linux-ng responder impacket-secretsdump impacket-psexec     impacket-GetNPUsers impacket-GetUserSPNs netexec nxc"

for tool in $DIRECT_TOOLS; do
    if [ "$1" = "$tool" ]; then
        log "Running tool directly: $*"
        exec "$@"
    fi
done

if [ "${1:-}" = "-t" ] || [ "${1:-}" = "--target" ] || [[ "${*}" == *"--target"* ]]; then
    if ! ip route 2>/dev/null | grep -q "default"; then
        warn "No default route detected. You may need --net=host:"
        warn "  docker run --rm --net=host perfodia $*"
        warn ""
    fi

    if [[ $(id -u) -ne 0 ]] && [[ ! " ${*} " =~ [[:space:]]--nmap-scan-type[[:space:]]sT([[:space:]]|$) ]] && [[ ! " ${*} " =~ [[:space:]]-sT([[:space:]]|$) ]]; then
        warn "Container is running rootless. Prefer --nmap-scan-type sT for reliable non-root scans."
        warn ""
    fi
fi

log "Starting Perfodia..."
exec python3 "$FRAMEWORK" "$@"
