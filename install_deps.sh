#!/usr/bin/env bash
# =============================================================================
# Perfodia — Debian/Ubuntu Dependency Installer
# =============================================================================
# Installs all system packages and tools required by the framework.
# Run as root or with sudo: sudo bash install_deps.sh
#
# Supported: Debian 11/12, Ubuntu 22.04/24.04, Kali Linux
#
# Options:
#   --minimal    Install only required tools (nmap, curl, dig, whois)
#   --full       Install everything including optional extras (default)
#   --no-msf     Skip Metasploit Framework installation
#   --dry-run    Show what would be installed without doing it
#   --help       Show this help message
# =============================================================================

set -euo pipefail

RED='[0;31m'
GREEN='[0;32m'
YELLOW='[1;33m'
CYAN='[0;36m'
BOLD='[1m'
NC='[0m'

INSTALL_MODE="full"
INSTALL_MSF=true
DRY_RUN=false
LOG_FILE="/tmp/perfodia_install_$(date +%Y%m%d_%H%M%S).log"

FFUF_URL_DEFAULT=""
FFUF_SHA256_DEFAULT=""
GOWITNESS_URL_DEFAULT=""
GOWITNESS_SHA256_DEFAULT=""
MSFINSTALL_URL_DEFAULT=""
MSFINSTALL_SHA256_DEFAULT=""

log()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*"; }
error()  { echo -e "${RED}[✗]${NC} $*"; }
info()   { echo -e "${CYAN}[i]${NC} $*"; }
header() { echo -e "
${BOLD}════════════════════════════════════════════${NC}"; echo -e "${BOLD}  $*${NC}"; echo -e "${BOLD}════════════════════════════════════════════${NC}
"; }

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

    # shellcheck disable=SC1091
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
        if dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
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
    pip3 install --break-system-packages "${packages[@]}" >> "$LOG_FILE" 2>&1 ||     pip3 install "${packages[@]}" >> "$LOG_FILE" 2>&1 ||     warn "pip install failed for: ${packages[*]}"
}

apt_has_package() {
    apt-cache show "$1" >/dev/null 2>&1
}

verified_download() {
    local url="$1"
    local sha256="$2"
    local destination="$3"

    if [[ -z "$url" || -z "$sha256" ]]; then
        warn "Skipping unverified download because URL/SHA256 was not provided"
        return 1
    fi

    if $DRY_RUN; then
        info "[DRY RUN] Would download and verify: $url"
        return 0
    fi

    curl -fsSL "$url" -o "$destination"
    echo "$sha256  $destination" | sha256sum -c - >> "$LOG_FILE" 2>&1
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

    local msf_url="${MSFINSTALL_URL:-$MSFINSTALL_URL_DEFAULT}"
    local msf_sha="${MSFINSTALL_SHA256:-$MSFINSTALL_SHA256_DEFAULT}"

    if verified_download "$msf_url" "$msf_sha" /tmp/msfinstall; then
        log "Installing Metasploit Framework from verified bootstrap..."
        chmod +x /tmp/msfinstall
        /tmp/msfinstall >> "$LOG_FILE" 2>&1 || warn "Metasploit install failed — install manually"
        rm -f /tmp/msfinstall
    else
        warn "Skipping Metasploit automatic install. Set MSFINSTALL_URL and MSFINSTALL_SHA256 to enable verified installation."
    fi
}

install_gobuster() {
    if command -v gobuster &>/dev/null; then
        info "gobuster already installed"
        return 0
    fi

    if apt_has_package gobuster; then
        apt_install gobuster
        return $?
    fi

    warn "gobuster package not available in apt repositories. Install manually for this distro."
}

install_ffuf() {
    if command -v ffuf &>/dev/null; then
        info "ffuf already installed"
        return 0
    fi

    if apt_has_package ffuf; then
        apt_install ffuf
        return $?
    fi

    local ffuf_url="${FFUF_URL:-$FFUF_URL_DEFAULT}"
    local ffuf_sha="${FFUF_SHA256:-$FFUF_SHA256_DEFAULT}"

    if verified_download "$ffuf_url" "$ffuf_sha" /tmp/ffuf.tgz; then
        tar -xzf /tmp/ffuf.tgz -C /usr/local/bin/ ffuf >> "$LOG_FILE" 2>&1
        chmod +x /usr/local/bin/ffuf
        rm -f /tmp/ffuf.tgz
        log "ffuf installed from verified archive"
    else
        warn "ffuf not installed automatically. Set FFUF_URL and FFUF_SHA256 or install via apt/manual package."
    fi
}

install_gowitness() {
    if command -v gowitness &>/dev/null; then
        info "gowitness already installed"
        return 0
    fi

    if apt_has_package gowitness; then
        apt_install gowitness
        return $?
    fi

    local gowitness_url="${GOWITNESS_URL:-$GOWITNESS_URL_DEFAULT}"
    local gowitness_sha="${GOWITNESS_SHA256:-$GOWITNESS_SHA256_DEFAULT}"

    if verified_download "$gowitness_url" "$gowitness_sha" /usr/local/bin/gowitness; then
        chmod +x /usr/local/bin/gowitness
        log "gowitness installed from verified binary"
    else
        warn "gowitness not installed automatically. Set GOWITNESS_URL and GOWITNESS_SHA256 or install manually."
    fi
}

install_responder() {
    if command -v responder &>/dev/null || command -v Responder.py &>/dev/null; then
        info "Responder already installed"
        return 0
    fi

    if apt_has_package responder; then
        apt_install responder
        return $?
    fi

    warn "Responder package not available in apt repositories. Install from a pinned commit manually if you need it."
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --minimal) INSTALL_MODE="minimal"; shift ;;
        --full)    INSTALL_MODE="full"; shift ;;
        --no-msf)  INSTALL_MSF=false; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h) usage ;;
        *)         error "Unknown option: $1"; usage ;;
    esac
done

header "Perfodia Dependency Installer"

if $DRY_RUN; then
    warn "DRY RUN MODE — nothing will be installed"
fi

check_root
check_os

info "Install mode: $INSTALL_MODE"
info "Log file: $LOG_FILE"
echo ""

header "Step 1: Updating Package Lists"
run_cmd "Updating apt cache..." apt-get update

header "Step 2: Essential Build Tools"
apt_install     build-essential     python3     python3-pip     python3-venv     python3-dev     git     wget     curl     unzip

header "Step 3: Required Tools"
apt_install     nmap     dnsutils     whois

if [[ "$INSTALL_MODE" == "minimal" ]]; then
    header "Step 4: Python Dependencies"
    pip_install PyYAML

    header "Minimal Installation Complete"
    log "Required tools installed. Run --full for all optional tools."
    exit 0
fi

header "Step 4: Reconnaissance Tools"
apt_install     dnsrecon     whois     netcat-openbsd     traceroute     net-tools

header "Step 5: Enumeration Tools"
apt_install     smbclient     nbtscan     snmp     snmp-mibs-downloader     onesixtyone     nikto     whatweb     ldap-utils

if [[ -f /etc/snmp/snmp.conf ]] && grep -q '^mibs' /etc/snmp/snmp.conf; then
    if ! $DRY_RUN; then
        sed -i 's/^mibs/#mibs/' /etc/snmp/snmp.conf
        log "Enabled SNMP MIB loading"
    fi
fi

header "Step 6: Exploitation Tools"
apt_install     hydra     john     hashcat     exploitdb     sqlmap
install_gobuster

header "Step 7: Python Packages"
pip_install     PyYAML     impacket     enum4linux-ng

if ! command -v crackmapexec &>/dev/null && ! command -v netexec &>/dev/null && ! command -v nxc &>/dev/null; then
    if apt_has_package netexec; then
        apt_install netexec
    else
        pip_install netexec || pip_install crackmapexec || warn "CrackMapExec/NetExec install failed — install manually"
    fi
fi

if ! command -v bloodhound-python &>/dev/null; then
    pip_install bloodhound || warn "bloodhound-python install failed — install manually"
fi

header "Step 8: Web Application & Screenshot Tools"
install_ffuf
install_gowitness
apt_install chromium-browser 2>/dev/null || apt_install chromium 2>/dev/null || true

header "Step 9: Responder"
install_responder

if $INSTALL_MSF; then
    header "Step 10: Metasploit Framework"
    install_metasploit
else
    info "Skipping Metasploit (--no-msf)"
fi

header "Step 11: Wordlists"
WORDLIST_DIR="/usr/share/wordlists"
mkdir -p "$WORDLIST_DIR"

if [[ ! -d "$WORDLIST_DIR/SecLists" ]]; then
    if $DRY_RUN; then
        info "[DRY RUN] Would clone SecLists"
    else
        log "Cloning SecLists (this may take a while)..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists" >> "$LOG_FILE" 2>&1 ||             warn "SecLists clone failed — install manually"
    fi
else
    info "SecLists already present"
fi

if [[ -f "$WORDLIST_DIR/rockyou.txt.gz" ]] && [[ ! -f "$WORDLIST_DIR/rockyou.txt" ]]; then
    if ! $DRY_RUN; then
        log "Decompressing rockyou.txt..."
        gunzip -k "$WORDLIST_DIR/rockyou.txt.gz"
    fi
elif [[ ! -f "$WORDLIST_DIR/rockyou.txt" ]]; then
    info "rockyou.txt not found — install kali-linux-default or download manually"
fi

apt_install dirb 2>/dev/null || true

header "Step 12: Verifying Installation"
TOOLS=(
    nmap
    dig
    whois
    curl
    python3
    pip3
    git
    smbclient
    nbtscan
    snmpwalk
    onesixtyone
    nikto
    whatweb
    hydra
    john
    hashcat
    searchsploit
    gobuster
    dnsrecon
    sqlmap
    ffuf
    gowitness
    ldapsearch
)

FOUND=0
MISSING=0

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log "  ✓ $tool"
        ((FOUND+=1))
    else
        warn "  ✗ $tool — not found"
        ((MISSING+=1))
    fi
done

PYTHON_TOOLS=(
    impacket-secretsdump
    impacket-psexec
    impacket-GetNPUsers
    impacket-GetUserSPNs
    enum4linux-ng
    bloodhound-python
)

for tool in "${PYTHON_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log "  ✓ $tool (Python)"
        ((FOUND+=1))
    else
        warn "  ✗ $tool (Python) — not found"
        ((MISSING+=1))
    fi
done

if command -v netexec &>/dev/null; then
    log "  ✓ netexec"
    ((FOUND+=1))
elif command -v nxc &>/dev/null; then
    log "  ✓ nxc"
    ((FOUND+=1))
elif command -v crackmapexec &>/dev/null; then
    log "  ✓ crackmapexec"
    ((FOUND+=1))
else
    warn "  ✗ crackmapexec/netexec/nxc — not found"
    ((MISSING+=1))
fi

if $INSTALL_MSF; then
    if command -v msfconsole &>/dev/null; then
        log "  ✓ msfconsole"
        ((FOUND+=1))
    else
        warn "  ✗ msfconsole — not found"
        ((MISSING+=1))
    fi
fi

if command -v responder &>/dev/null || command -v Responder.py &>/dev/null; then
    log "  ✓ responder"
    ((FOUND+=1))
else
    warn "  ✗ responder — not found"
    ((MISSING+=1))
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
info "  1. cd perfodia/"
info "  2. pip3 install -r requirements.txt"
info "  3. sudo python3 perfodia.py --check-tools"
info "  4. sudo python3 perfodia.py -t <target> -m full -v"
echo ""
