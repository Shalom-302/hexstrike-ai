# HexStrike AI server image for the Hermes lab.
#
# Runs hexstrike_server.py (Flask HTTP API on :8888). This image is NOT meant
# to be published on the host or the internet: in the lab it is reachable only
# from the MCP gateway (hexstrike-link network) and reaches lab targets over the
# shasec network. See docker/README-lab.md.
#
# Base: Kali rolling, which the project documents as the supported platform and
# which already packages the recon/web tooling the default allowlist uses.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    HEXSTRIKE_HOST=0.0.0.0 \
    HEXSTRIKE_PORT=8888

# System packages:
#  - python toolchain to run the server
#  - the security tools wired into the DEFAULT gateway allowlist. These are
#    chosen to be COMPLEMENTARY to SHASEC (which already owns nuclei/ffuf/nikto/
#    httpx/katana/subfinder/whatweb/zap and native sqli/xss/jwt/... verifiers):
#      nmap           shared foundation (advanced NSE)
#      amass masscan  recon breadth SHASEC lacks
#      sqlmap wpscan dalfox arjun wafw00f dotdotpwn  deep offensive web
#      hydra          online credential attacks (SHASEC has none)
# Add more tools here only when you also add them to the gateway allowlist.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        ca-certificates curl dnsutils \
        nmap amass masscan sqlmap wpscan dalfox arjun wafw00f dotdotpwn hydra \
        libcap2-bin \
        build-essential python3-dev libffi-dev pkg-config libssl-dev cargo \
    && rm -rf /var/lib/apt/lists/* \
    # Let the non-root user run SYN/OS scans. The capability is still bounded by
    # what the container is granted (cap_add: NET_RAW/NET_ADMIN in compose);
    # without that grant this setcap is simply inert.
    && setcap cap_net_raw,cap_net_admin+eip "$(command -v nmap)"

# Isolated virtualenv (Kali's Python is externally-managed / PEP 668).
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Python dependencies actually needed to BOOT the server. selenium, aiohttp,
# bs4 and mitmproxy are imported unconditionally at module top; pwntools/angr
# are imported lazily inside endpoints (not on the default allowlist), so they
# are intentionally omitted to keep the image lean.
RUN pip install \
        "flask>=2.3.0,<4.0.0" \
        "requests>=2.31.0,<3.0.0" \
        "psutil>=5.9.0,<6.0.0" \
        "fastmcp>=0.2.0,<1.0.0" \
        "aiohttp>=3.8.0,<4.0.0" \
        "beautifulsoup4>=4.12.0,<5.0.0" \
        "selenium>=4.15.0,<5.0.0" \
        "webdriver-manager>=4.0.0,<5.0.0" \
        "mitmproxy>=9.0.0,<11.0.0"

WORKDIR /opt/hexstrike
COPY hexstrike_server.py /opt/hexstrike/hexstrike_server.py

# Run as a non-root user. The security tools used by the default allowlist do
# not need root; raise privileges here only if you add tools that require them.
RUN useradd --create-home --uid 10001 hexstrike \
    && chown -R hexstrike:hexstrike /opt/hexstrike
USER hexstrike

EXPOSE 8888

HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
    CMD curl -fsS "http://127.0.0.1:${HEXSTRIKE_PORT}/health" || exit 1

CMD ["python3", "hexstrike_server.py"]
