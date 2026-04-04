###############################################################################
# PentestFW Docker Image
###############################################################################
# Multi-target build:
#   docker build -t pentestfw .                          # full (default)
#   docker build -t pentestfw:minimal --target minimal . # scanning only
#
# See DOCKER.md for complete usage instructions.
###############################################################################

# ─── Stage 1: Base — Python + core system packages ─────────────────────────

FROM debian:bookworm-slim AS base

LABEL maintainer="pentestfw"
LABEL description="PentestFW — Network Penetration Testing Framework"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    TERM=xterm-256color

# Core system dependencies (always needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates \
        curl \
        wget \
        git \
        dnsutils \
        whois \
        nmap \
        net-tools \
        iputils-ping \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Create framework directory and non-root user with sudo
RUN groupadd -r pentester && \
    useradd -r -g pentester -m -s /bin/bash pentester && \
    apt-get update && apt-get install -y --no-install-recommends sudo && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/pentestfw

# Copy framework code
COPY --chown=pentester:pentester . /opt/pentestfw/

# Install Python dependencies
RUN pip3 install --no-cache-dir PyYAML && \
    chmod +x /opt/pentestfw/pentestfw.py

# Create persistent volumes for reports and configs
RUN mkdir -p /opt/pentestfw/reports /opt/pentestfw/logs && \
    chown -R pentester:pentester /opt/pentestfw

# ─── Stage 2: Minimal — base + just enough for recon/scanning ──────────────

FROM base AS minimal

LABEL variant="minimal"

# Minimal extras for basic enumeration
RUN apt-get update && apt-get install -y --no-install-recommends \
        netcat-openbsd \
        traceroute \
        nbtscan \
        snmp \
        snmp-mibs-downloader \
    && rm -rf /var/lib/apt/lists/*

# Enable SNMP MIBs
RUN if [ -f /etc/snmp/snmp.conf ]; then \
        sed -i 's/^mibs/#mibs/' /etc/snmp/snmp.conf; \
    fi

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]

# ─── Stage 3: Full — all tools including exploitation & post-exploitation ──

FROM base AS full

LABEL variant="full"

# ── Enumeration tools ──
RUN apt-get update && apt-get install -y --no-install-recommends \
        smbclient \
        nbtscan \
        snmp \
        snmp-mibs-downloader \
        onesixtyone \
        nikto \
        whatweb \
        ldap-utils \
        netcat-openbsd \
        traceroute \
        dnsrecon \
    && rm -rf /var/lib/apt/lists/*

# ── Exploitation tools ──
RUN apt-get update && apt-get install -y --no-install-recommends \
        hydra \
        john \
        hashcat \
        exploitdb \
        sqlmap \
        dirb \
    && rm -rf /var/lib/apt/lists/*

# ── Python security packages ──
RUN pip3 install --no-cache-dir \
        impacket \
        enum4linux-ng \
    && rm -rf /root/.cache

# ── Gobuster (static binary from GitHub releases) ──
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        GOARCH="linux-amd64"; \
    elif [ "$ARCH" = "arm64" ]; then \
        GOARCH="linux-arm64"; \
    else \
        GOARCH=""; \
    fi && \
    if [ -n "$GOARCH" ]; then \
        LATEST=$(curl -sL https://api.github.com/repos/OJ/gobuster/releases/latest \
            | grep "tag_name" | head -1 | cut -d '"' -f 4) && \
        curl -sL "https://github.com/OJ/gobuster/releases/download/${LATEST}/gobuster_${LATEST#v}_${GOARCH}.tar.gz" \
            -o /tmp/gobuster.tar.gz && \
        tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin/ gobuster 2>/dev/null || \
        tar -xzf /tmp/gobuster.tar.gz -C /tmp/ && \
        find /tmp -name gobuster -type f -exec mv {} /usr/local/bin/gobuster \; 2>/dev/null; \
        chmod +x /usr/local/bin/gobuster 2>/dev/null; \
        rm -f /tmp/gobuster.tar.gz; \
    fi

# ── Responder ──
RUN git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder 2>/dev/null && \
    ln -sf /opt/Responder/Responder.py /usr/local/bin/responder && \
    chmod +x /opt/Responder/Responder.py || true

# ── Enable SNMP MIBs ──
RUN if [ -f /etc/snmp/snmp.conf ]; then \
        sed -i 's/^mibs/#mibs/' /etc/snmp/snmp.conf; \
    fi

# ── Wordlists (small curated set — full SecLists is 1GB+) ──
RUN mkdir -p /usr/share/wordlists && \
    # dirb common wordlist is installed with dirb package
    # Create a small default username list
    printf '%s\n' admin root administrator user test guest \
        operator service backup ftp www-data mysql postgres \
        > /usr/share/wordlists/common_users.txt && \
    # Create a small password list for quick testing
    printf '%s\n' password admin 123456 12345678 root toor \
        letmein welcome monkey dragon master qwerty \
        login abc123 starwars trustno1 iloveyou \
        > /usr/share/wordlists/quick_passwords.txt

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Fix ownership
RUN chown -R pentester:pentester /opt/pentestfw

USER pentester
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
