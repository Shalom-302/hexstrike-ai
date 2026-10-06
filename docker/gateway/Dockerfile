# HexStrike MCP gateway image.
#
# A small streamable-HTTP MCP server that sits between Hermes and HexStrike.
# It exposes ONLY an explicit, deny-by-default allowlist of tools and forwards
# each allowed call to the HexStrike HTTP API. It never maps HexStrike's
# arbitrary-execution endpoints (/api/command, /api/python/execute,
# /api/files/*, payload/exploit generation, msfvenom, ...).
FROM python:3.11-slim

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8888 \
    HEXSTRIKE_URL=http://hexstrike:8888

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/gateway
COPY requirements.txt /opt/gateway/requirements.txt
RUN pip install -r requirements.txt
COPY hexstrike_gateway.py /opt/gateway/hexstrike_gateway.py

RUN useradd --create-home --uid 10002 gateway
USER gateway

EXPOSE 8888

# Liveness: the streamable-http endpoint answers (405 on bare GET is fine —
# it proves the ASGI app is up). We only check that the port is serving.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD curl -fsS -o /dev/null "http://127.0.0.1:${GATEWAY_PORT}/mcp" \
        || curl -fsS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${GATEWAY_PORT}/mcp" | grep -qE '^(405|400|406)$' \
        || exit 1

CMD ["python3", "hexstrike_gateway.py"]
