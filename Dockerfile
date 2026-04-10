###############################################################################
# Perfodia Docker Image
###############################################################################
# Multi-target build:
#   docker build -t perfodia .                          # full (default)
#   docker build -t perfodia:minimal --target minimal . # scanning only
###############################################################################

FROM debian:bookworm-slim AS base

LABEL maintainer="perfodia"
LABEL description="Perfodia — Network Penetration Testing Framework"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    TERM=xterm-256color

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
        sudo \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r pentester && \
    useradd -r -g pentester -m -s /bin/bash pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

WORKDIR /opt/perfodia
COPY --chown=pentester:pentester . /opt/perfodia/

RUN pip3 install --no-cache-dir PyYAML && \
    chmod +x /opt/perfodia/perfodia.py && \
    mkdir -p /opt/perfodia/reports /opt/perfodia/logs && \
    chown -R pentester:pentester /opt/perfodia

# ===================================================================
FROM base AS minimal
LABEL variant="minimal"

RUN sed -i 's/Components: main/Components: main contrib non-free non-free-firmware/' /etc/apt/sources.list.d/debian.sources && \
    apt-get update

RUN apt-get install -y --no-install-recommends \
        netcat-openbsd \
        traceroute \
        nbtscan \
        snmp \
        snmp-mibs-downloader \
    && rm -rf /var/lib/apt/lists/*

RUN if [ -f /etc/snmp/snmp.conf ]; then \
        sed -i 's/^mibs/#mibs/' /etc/snmp/snmp.conf; \
    fi

COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]

# ===================================================================
FROM base AS full
LABEL variant="full"

# Enable contrib + non-free repositories
RUN sed -i 's/Components: main/Components: main contrib non-free non-free-firmware/' /etc/apt/sources.list.d/debian.sources && \
    apt-get update

RUN apt-get install -y --no-install-recommends \
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
        ffuf \
        hydra \
        john \
        hashcat \
        sqlmap \
        dirb \
        gobuster \
        chromium \
    && rm -rf /var/lib/apt/lists/*

# === NetExec (build deps + Rust + install) ===
# git is intentionally kept so SecLists/Exploit-DB/Responder work
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        python3-dev \
        build-essential \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
        libssl-dev \
    && curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable \
    && . "$HOME/.cargo/env" \
    && pip3 install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec.git \
    && rm -rf /root/.cargo /root/.rustup /root/.cache/pip \
    && apt-get purge -y python3-dev build-essential libffi-dev libxml2-dev libxslt1-dev libssl-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# SecLists
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists && \
    ln -s /usr/share/wordlists/SecLists /usr/share/seclists

# Exploit-DB / searchsploit (active GitLab repo)
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
    chmod +x /opt/exploitdb/searchsploit && \
    ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# Python tools (enum4linux-ng installed from GitHub because it's not on PyPI)
RUN pip3 install --no-cache-dir \
        impacket \
        git+https://github.com/cddmp/enum4linux-ng.git \
        bloodhound \
        rich \
    && rm -rf /root/.cache

ARG RESPONDER_REF=""
RUN if [ -n "$RESPONDER_REF" ]; then \
        git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder && \
        cd /opt/Responder && \
        git fetch --depth 1 origin "$RESPONDER_REF" && \
        git checkout --detach "$RESPONDER_REF" && \
        ln -sf /opt/Responder/Responder.py /usr/local/bin/responder && \
        chmod +x /opt/Responder/Responder.py; \
    else \
        echo "Skipping Responder Git install (set --build-arg RESPONDER_REF=<commit> to enable verified pinning)."; \
    fi

ARG MSFINSTALL_URL=""
ARG MSFINSTALL_SHA256=""
RUN if [ -n "$MSFINSTALL_URL" ] && [ -n "$MSFINSTALL_SHA256" ]; then \
        curl -fsSL "$MSFINSTALL_URL" -o /tmp/msfinstall && \
        echo "$MSFINSTALL_SHA256  /tmp/msfinstall" | sha256sum -c - && \
        chmod +x /tmp/msfinstall && \
        /tmp/msfinstall >> /dev/null 2>&1 || true; \
        rm -f /tmp/msfinstall; \
    else \
        echo "Skipping Metasploit bootstrap (set MSFINSTALL_URL and MSFINSTALL_SHA256 build args to enable verified installation)."; \
    fi

RUN if [ -f /etc/snmp/snmp.conf ]; then \
        sed -i 's/^mibs/#mibs/' /etc/snmp/snmp.conf; \
    fi

RUN mkdir -p /usr/share/wordlists && \
    printf '%s\n' admin root administrator user test guest \
        operator service backup ftp www-data mysql postgres \
        > /usr/share/wordlists/common_users.txt && \
    printf '%s\n' password admin 123456 12345678 root toor \
        letmein welcome monkey dragon master qwerty \
        login abc123 starwars trustno1 iloveyou \
        > /usr/share/wordlists/quick_passwords.txt

COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && \
    chown -R pentester:pentester /opt/perfodia /usr/share/wordlists /opt/exploitdb /usr/share/seclists

USER pentester
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]