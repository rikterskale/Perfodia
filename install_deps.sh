#!/usr/bin/env bash
# =============================================================================
# PentestFW — Debian/Ubuntu Dependency Installer
# =============================================================================
# Installs all system packages and tools required by the framework.
# Run as root or with sudo: sudo bash install_deps.sh
#
# Supported: Debian 11/12, Ubuntu 22.04/24.04, Kali Linux
#
# Options:
#   --minimal    Install only required tools (nmap, curl, dig, whois)
#   --full       Install everything including Metasploit (default)
#   --no-msf     Skip Metasploit Framework installation
#   --dry-run    Show what would be installed without doing it
#   --help       Show this help message
# =============================================================================

set -euo pipefail

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Defaults ──
INSTALL_MODE="full"
INSTALL_MSF=true
DRY_RUN=false
LOG_FILE="/tmp/pentestfw_install_$(date +%Y%m%d_%H%M%S).log"

# ── Functions ──

log()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
error()  { echo -e "${RED}[✗]${NC} $*"; }
info()   { echo -e "${CYAN}[i]${NC} $*"; }
header() { echo -e "\n${BOLD}════════════════════════════════════════════${NC}"; echo -e "${BOLD}  $*${NC}"; echo -e "${BOLD}════════════════════════════════════════════${NC}\n"; }

usage() {
    head -n 14 "$0" | tail -n 8
    exit 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo bash $0"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS. This script supports Debian/Ubuntu/Kali only."
        exit 1
    fi

    source /etc/os-release

    case "$ID" in
        debian|ubuntu|kali|parrot|linuxmint|pop)
            log "Detected OS: $PRETTY_NAME"
            ;;
        *)
            error "Unsupported OS: $ID. This script supports Debian-based distributions."
            exit 1
            ;;
    esac
}

run_cmd() {
    local desc="$1"
    shift
    if $DRY_RUN; then
        info "[DRY RUN] Would run: $*"
        return 0
    fi
    log "$desc"
    if ! "$@" >> "$LOG_FILE" 2>&1; then
        warn "Command failed: $* (check $LOG_FILE for details)"
        return 1
    fi
}

apt_install() {
    local packages=("$@")
    local to_install=()

    for pkg in "${packages[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            info "$pkg is already installed"
        else
            to_install+=("$pkg")
        fi
    done

    if [[ ${#to_install[@]} -eq 0 ]]; then
        log "All packages already installed"
        return 0
    fi

    if $DRY_RUN; then
        info "[DRY RUN] Would install: ${to_install[*]}"
        return 0
    fi

    log "Installing ${#to_install[@]} packages: ${to_install[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${to_install[@]}" >> "$LOG_FILE" 2>&1
}

pip_install() {
    local packages=("$@")
    if $DRY_RUN; then
        info "[DRY RUN] Would pip install: ${packages[*]}"
        return 0
    fi
    log "Installing Python packages: ${packages[*]}"
    pip3 install --break-system-packages "${packages[@]}" >> "$LOG_FILE" 2>&1 || \
    pip3 install "${packages[@]}" >> "$LOG_FILE" 2>&1 || \
    warn "pip install failed for: ${packages[*]}"
}

install_metasploit() {
    if command -v msfconsole &>/dev/null; then
        info "Metasploit Framework already installed"
        return 0
    fi

    if $DRY_RUN; then
        info "[DRY RUN] Would install Metasploit Framework"
        return 0
    fi

    log "Installing Metasploit Framework..."
    curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall 2>/dev/null
    if [[ -f /tmp/msfinstall ]]; then
        chmod +x /tmp/msfinstall
        /tmp/msfinstall >> "$LOG_FILE" 2>&1 || warn "Metasploit install failed — install manually"
        rm -f /tmp/msfinstall
    else
        warn "Could not download Metasploit installer. Install manually from https://metasploit.com"
    fi
}

install_gobuster() {
    if command -v gobuster &>/dev/null; then
        info "gobuster already installed"
        return 0
    fi

    # Try apt first (available on Kali)
    if apt-cache show gobuster &>/dev/null 2>&1; then
        apt_install gobuster
        return $?
    fi

    if $DRY_RUN; then
        info "[DRY RUN] Would install gobuster via Go"
        return 0
    fi

    # Install via Go if available
    if command -v go &>/dev/null; then
        log "Installing gobuster via Go..."
        go install github.com/OJ/gobuster/v3@latest >> "$LOG_FILE" 2>&1
        # Link to /usr/local/bin if installed to ~/go/bin
        if [[ -f ~/go/bin/gobuster ]]; then
            ln -sf ~/go/bin/gobuster /usr/local/bin/gobuster
        fi
    else
        warn "gobuster: not in apt and Go not installed. Install Go first or install gobuster manually."
    fi
}

install_responder() {
    if command -v responder &>/dev/null || command -v Responder.py &>/dev/null; then
        info "Responder already installed"
        return 0
    fi

    if $DRY_RUN; then
        info "[DRY RUN] Would clone Responder from GitHub"
        return 0
    fi

    log "Installing Responder from GitHub..."
    if [[ -d /opt/Responder ]]; then
        cd /opt/Responder && git pull >> "$LOG_FILE" 2>&1
    else
        git clone https://github.com/lgandx/Responder.git /opt/Responder >> "$LOG_FILE" 2>&1
    fi

    if [[ -f /opt/Responder/Responder.py ]]; then
        ln -sf /opt/Responder/Responder.py /usr/local/bin/responder
        chmod +x /opt/Responder/Responder.py
    fi
}

# ── Parse Arguments ──

while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal) INSTALL_MODE="minimal"; shift ;;
        --full)    INSTALL_MODE="full";    shift ;;
        --no-msf)  INSTALL_MSF=false;     shift ;;
        --dry-run) DRY_RUN=true;          shift ;;
        --help|-h) usage ;;
        *)         error "Unknown option: $1"; usage ;;
    esac
done

# ── Main ──

header "PentestFW Dependency Installer"

if $DRY_RUN; then
    warn "DRY RUN MODE — nothing will be installed"
fi

check_root
check_os

info "Install mode: $INSTALL_MODE"
info "Log file: $LOG_FILE"
echo ""

# ── Step 1: Update package lists ──

header "Step 1: Updating Package Lists"
run_cmd "Updating apt cache..." apt-get update

# ── Step 2: Essential build tools ──

header "Step 2: Essential Build Tools"
apt_install \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    wget \
    curl \
    unzip

# ── Step 3: Required tools (always installed) ──

header "Step 3: Required Tools"
apt_install \
    nmap \
    dnsutils \
    whois

if [[ "$INSTALL_MODE" == "minimal" ]]; then
    header "Step 4: Python Dependencies"
    pip_install PyYAML

    header "Minimal Installation Complete"
    log "Required tools installed. Run --full for all optional tools."
    exit 0
fi

# ── Step 4: Networking & recon tools ──

header "Step 4: Reconnaissance Tools"
apt_install \
    dnsrecon \
    whois \
    netcat-openbsd \
    traceroute \
    net-tools

# ── Step 5: Enumeration tools ──

header "Step 5: Enumeration Tools"
apt_install \
    smbclient \
    nbtscan \
    snmp \
    snmp-mibs-downloader \
    onesixtyone \
    nikto \
    whatweb \
    ldap-utils

# Enable MIBs for SNMP (disabled by default on Debian/Ubuntu)
if [[ -f /etc/snmp/snmp.conf ]]; then
    if grep -q "^mibs" /etc/snmp/snmp.conf; then
        if ! $DRY_RUN; then
            sed -i 's/^mibs/#mibs/' /etc/snmp/snmp.conf
            log "Enabled SNMP MIB loading"
        fi
    fi
fi

# ── Step 6: Exploitation tools ──

header "Step 6: Exploitation Tools"
apt_install \
    hydra \
    john \
    hashcat \
    exploitdb \
    sqlmap

install_gobuster

# ── Step 7: Python security packages ──

header "Step 7: Python Packages"
pip_install \
    PyYAML \
    impacket \
    enum4linux-ng

# crackmapexec / netexec (successor)
if ! command -v crackmapexec &>/dev/null && ! command -v nxc &>/dev/null; then
    pip_install netexec || pip_install crackmapexec || warn "CrackMapExec/NetExec install failed — install manually"
fi

# bloodhound-python (AD data collection)
if ! command -v bloodhound-python &>/dev/null; then
    pip_install bloodhound || warn "bloodhound-python install failed — install manually"
fi

# ── Step 8: Web Application Testing Tools ──

header "Step 8: Web Application & Screenshot Tools"

# ffuf (fast web fuzzer — Go binary from GitHub)
if ! command -v ffuf &>/dev/null; then
    if $DRY_RUN; then
        info "[DRY RUN] Would install ffuf"
    else
        ARCH=$(dpkg --print-architecture)
        if [ "$ARCH" = "amd64" ]; then
            FFUF_ARCH="linux_amd64"
        elif [ "$ARCH" = "arm64" ]; then
            FFUF_ARCH="linux_arm64"
        else
            FFUF_ARCH=""
        fi
        if [ -n "$FFUF_ARCH" ]; then
            log "Installing ffuf..."
            FFUF_VER=$(curl -sL https://api.github.com/repos/ffuf/ffuf/releases/latest \
                | grep "tag_name" | head -1 | cut -d '"' -f 4)
            if [ -n "$FFUF_VER" ]; then
                curl -sL "https://github.com/ffuf/ffuf/releases/download/${FFUF_VER}/ffuf_${FFUF_VER#v}_${FFUF_ARCH}.tar.gz" \
                    -o /tmp/ffuf.tar.gz && \
                tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf 2>/dev/null && \
                chmod +x /usr/local/bin/ffuf && \
                rm -f /tmp/ffuf.tar.gz && \
                log "ffuf installed" || warn "ffuf install failed"
            fi
        fi
    fi
else
    info "ffuf already installed"
fi

# gowitness (screenshot tool — Go binary from GitHub)
if ! command -v gowitness &>/dev/null; then
    if $DRY_RUN; then
        info "[DRY RUN] Would install gowitness"
    else
        ARCH=$(dpkg --print-architecture)
        if [ "$ARCH" = "amd64" ]; then
            GW_ARCH="linux-amd64"
        elif [ "$ARCH" = "arm64" ]; then
            GW_ARCH="linux-arm64"
        else
            GW_ARCH=""
        fi
        if [ -n "$GW_ARCH" ]; then
            log "Installing gowitness..."
            GW_VER=$(curl -sL https://api.github.com/repos/sensepost/gowitness/releases/latest \
                | grep "tag_name" | head -1 | cut -d '"' -f 4)
            if [ -n "$GW_VER" ]; then
                curl -sL "https://github.com/sensepost/gowitness/releases/download/${GW_VER}/gowitness-${GW_VER}-${GW_ARCH}" \
                    -o /usr/local/bin/gowitness 2>/dev/null && \
                chmod +x /usr/local/bin/gowitness && \
                log "gowitness installed" || warn "gowitness install failed"
            fi
        fi
    fi
else
    info "gowitness already installed"
fi

# chromium headless (fallback screenshot backend)
apt_install chromium-browser 2>/dev/null || apt_install chromium 2>/dev/null || true

# ── Step 9: Responder ──

header "Step 9: Responder"
install_responder

# ── Step 10: Metasploit Framework ──

if $INSTALL_MSF; then
    header "Step 10: Metasploit Framework"
    install_metasploit
else
    info "Skipping Metasploit (--no-msf)"
fi

# ── Step 11: Wordlists ──

header "Step 11: Wordlists"
WORDLIST_DIR="/usr/share/wordlists"
mkdir -p "$WORDLIST_DIR"

# SecLists
if [[ ! -d "$WORDLIST_DIR/SecLists" ]]; then
    if $DRY_RUN; then
        info "[DRY RUN] Would clone SecLists"
    else
        log "Cloning SecLists (this may take a while)..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists" >> "$LOG_FILE" 2>&1 || \
            warn "SecLists clone failed — install manually"
    fi
else
    info "SecLists already present"
fi

# rockyou.txt
if [[ -f "$WORDLIST_DIR/rockyou.txt.gz" ]] && [[ ! -f "$WORDLIST_DIR/rockyou.txt" ]]; then
    if ! $DRY_RUN; then
        log "Decompressing rockyou.txt..."
        gunzip -k "$WORDLIST_DIR/rockyou.txt.gz"
    fi
elif [[ ! -f "$WORDLIST_DIR/rockyou.txt" ]]; then
    info "rockyou.txt not found — install kali-linux-default or download manually"
fi

# dirb wordlists
apt_install dirb 2>/dev/null || true

# ── Step 12: Verify Installation ──

header "Step 12: Verifying Installation"

TOOLS=(
    "nmap"
    "dig"
    "whois"
    "curl"
    "python3"
    "pip3"
    "git"
    "smbclient"
    "nbtscan"
    "snmpwalk"
    "onesixtyone"
    "nikto"
    "whatweb"
    "hydra"
    "john"
    "hashcat"
    "searchsploit"
    "gobuster"
    "dnsrecon"
    "sqlmap"
    "ffuf"
    "gowitness"
    "ldapsearch"
)

FOUND=0
MISSING=0

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log "  ✓ $tool"
        ((FOUND++))
    else
        warn "  ✗ $tool — not found"
        ((MISSING++))
    fi
done

# Python tools
PYTHON_TOOLS=(
    "impacket-secretsdump"
    "impacket-psexec"
    "impacket-GetNPUsers"
    "impacket-GetUserSPNs"
    "enum4linux-ng"
    "bloodhound-python"
)

for tool in "${PYTHON_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log "  ✓ $tool (Python)"
        ((FOUND++))
    else
        warn "  ✗ $tool (Python) — not found"
        ((MISSING++))
    fi
done

# Metasploit
if $INSTALL_MSF; then
    if command -v msfconsole &>/dev/null; then
        log "  ✓ msfconsole"
        ((FOUND++))
    else
        warn "  ✗ msfconsole — not found"
        ((MISSING++))
    fi
fi

# Responder
if command -v responder &>/dev/null || command -v Responder.py &>/dev/null; then
    log "  ✓ responder"
    ((FOUND++))
else
    warn "  ✗ responder — not found"
    ((MISSING++))
fi

echo ""
header "Installation Summary"
log "Tools found:   $FOUND"
if [[ $MISSING -gt 0 ]]; then
    warn "Tools missing: $MISSING (see warnings above)"
else
    log "All tools installed successfully!"
fi
info "Full log: $LOG_FILE"

echo ""
log "Next steps:"
info "  1. cd pentestfw/"
info "  2. pip3 install -r requirements.txt"
info "  3. sudo python3 pentestfw.py --check-tools"
info "  4. sudo python3 pentestfw.py -t <target> -m full -v"
echo ""
