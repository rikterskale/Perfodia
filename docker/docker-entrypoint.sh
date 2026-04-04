#!/usr/bin/env bash
###############################################################################
# Perfodia Docker Entrypoint
###############################################################################
# Handles:
#   - Running the framework with proper arguments
#   - Passing through raw nmap / tool commands
#   - First-run environment validation
###############################################################################

set -euo pipefail

FRAMEWORK="/opt/perfodia/perfodia.py"

# ── Color helpers ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[perfodia]${NC} $*"; }
warn() { echo -e "${YELLOW}[perfodia]${NC} $*"; }
err()  { echo -e "${RED}[perfodia]${NC} $*" >&2; }

# ── First-run: show banner and validate environment ──
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
    echo "  # Check installed tools"
    echo "  docker run --rm perfodia --check-tools"
    echo ""
    echo "  # Scan a target (use --net=host for proper network access)"
    echo "  docker run --rm --net=host perfodia -t 192.168.1.100 -m scan -v"
    echo ""
    echo "  # Full pentest with reports saved to host"
    echo "  docker run --rm --net=host -v ./reports:/opt/perfodia/reports \\"
    echo "      perfodia -t 192.168.1.0/24 -m full -v"
    echo ""
    echo "  # Custom nmap options"
    echo "  docker run --rm --net=host perfodia -t 192.168.1.100 -m scan \\"
    echo "      --nmap-extra '-sU -Pn' -v"
    echo ""
    echo "  # Interactive shell inside the container"
    echo "  docker run --rm -it --net=host perfodia shell"
    echo ""
    echo "  # Run a raw tool directly"
    echo "  docker run --rm --net=host perfodia nmap -sV -p 80 192.168.1.100"
    echo ""

    # If explicitly asked for --help, also show the framework help
    if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
        echo "─── Framework Help ───────────────────────────────────────────"
        python3 "$FRAMEWORK" --help
    fi
    exit 0
fi

# ── Special commands ──

# "shell" → drop into bash
if [ "$1" = "shell" ] || [ "$1" = "bash" ] || [ "$1" = "sh" ]; then
    log "Dropping into interactive shell..."
    exec /bin/bash
fi

# "check" / "check-tools" shortcut
if [ "$1" = "check" ] || [ "$1" = "check-tools" ]; then
    exec python3 "$FRAMEWORK" --check-tools
fi

# If the first argument is a known external tool, run it directly
# (lets you do: docker run perfodia nmap -sV 192.168.1.1)
DIRECT_TOOLS="nmap masscan nikto gobuster hydra snmpwalk whatweb searchsploit \
    smbclient rpcclient dig whois john hashcat sqlmap dnsrecon nbtscan curl \
    enum4linux-ng responder impacket-secretsdump impacket-psexec \
    impacket-GetNPUsers impacket-GetUserSPNs"

for tool in $DIRECT_TOOLS; do
    if [ "$1" = "$tool" ]; then
        log "Running tool directly: $*"
        exec "$@"
    fi
done

# ── Check network capabilities ──
if [ "${1:-}" = "-t" ] || [ "${1:-}" = "--target" ] || [[ "${*}" == *"--target"* ]]; then
    # Check if we can access the network
    if ! ip route 2>/dev/null | grep -q "default"; then
        warn "No default route detected. You may need --net=host:"
        warn "  docker run --rm --net=host perfodia $*"
        warn ""
    fi

    # Check for SYN scan capability (needs NET_ADMIN or host networking)
    if ! nmap --privileged -sS 127.0.0.1 -p 1 2>/dev/null | grep -q "1/tcp" 2>/dev/null; then
        # Can't do SYN scans — check if user specified sT
        if [[ ! "${*}" == *"sT"* ]] && [[ ! "${*}" == *"nmap-scan-type"* ]]; then
            warn "SYN scan may not work without --privileged or --net=host."
            warn "Consider adding: --nmap-scan-type sT"
            warn ""
        fi
    fi
fi

# ── Run the framework ──
log "Starting perfodia..."
exec python3 "$FRAMEWORK" "$@"
