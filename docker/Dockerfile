FROM kalilinux/kali-rolling

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install base packages
RUN apt-get update && apt-get install -y \
    golang \
    git \
    curl \
    wget \
    sqlmap \
    feroxbuster \
    ffuf \
    chromium \
    python3 \
    whois \
    dnsutils \
    nmap \
    metasploit-framework \
    responder \
    hashcat \
    john \
    commix \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools via pdtm
ENV GOPATH=/root/go
ENV PATH="${GOPATH}/bin:/root/.pdtm/go/bin:${PATH}"
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest \
    && pdtm -install-all

# Install uv for Python package management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Install Python packages with uv (bypass externally managed check)
RUN uv pip install --system --break-system-packages playwright \
    && playwright install chromium --with-deps

# Additional security testing tools for playbook support
RUN uv pip install --system --break-system-packages \
    impacket \
    crackmapexec \
    jwt-tool \
    tplmap \
    nosqlmap

# SAST tools
# Install ast-grep via cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install ast-grep --locked

# Install Python SAST tools via uv
RUN uv tool install semgrep && \
    uv tool install bandit && \
    uv tool install pip-audit

# Install opengrep (open-source semgrep fork with additional features)
RUN curl -fsSL -o /tmp/opengrep_install.sh https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh && \
    bash /tmp/opengrep_install.sh && \
    rm /tmp/opengrep_install.sh

# Install Go-based SAST tools
RUN go install github.com/zricethezav/gitleaks/v8@latest && \
    go install golang.org/x/vuln/cmd/govulncheck@latest

RUN go install github.com/hahwul/dalfox/v2@latest

# Install Grype for dependency scanning
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy for container/dependency scanning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Create working directories
RUN mkdir -p /feroxmute/workdir/{orchestrator,recon,scanner,exploit,scripts} \
    /feroxmute/artifacts/{downloads,evidence} \
    /feroxmute/screenshots \
    /feroxmute/shared

WORKDIR /feroxmute

# Java deserialization tool
RUN mkdir -p /opt/ysoserial && \
    wget -O /opt/ysoserial/ysoserial.jar \
    https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Default command keeps container running
CMD ["tail", "-f", "/dev/null"]
