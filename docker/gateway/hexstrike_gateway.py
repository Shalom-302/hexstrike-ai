#!/usr/bin/env python3
"""
HexStrike MCP Gateway
=====================

A small, dedicated MCP server that sits between Hermes and the HexStrike
HTTP API. Its only jobs are:

  1. Expose, over streamable-HTTP MCP, an EXPLICIT, deny-by-default allowlist
     of security tools — nothing else is reachable through it.
  2. Forward each allowed call to the HexStrike server's ``/api/tools/<tool>``
     endpoint and return the result.

Design rules (why this file is deliberately boring):
  * Deny by default. A tool is exposed only if it is both (a) in the configured
    allowlist AND (b) implemented here as a typed wrapper (or reachable via the
    opt-in generic passthrough, which is itself still constrained to the
    allowlist and to ``/api/tools/*``).
  * The gateway NEVER maps HexStrike's arbitrary-execution surface:
    ``/api/command``, ``/api/python/execute``, ``/api/files/*``,
    ``/api/payloads/generate``, msfvenom/metasploit, etc. Those endpoints stay
    on the HexStrike container, which is not routable from Hermes.
  * Configuration is environment-driven so the same image serves different
    labs with different allowlists.

Environment:
  HEXSTRIKE_URL                  HexStrike API base URL (default http://hexstrike:8888)
  HEXSTRIKE_ALLOWED_TOOLS        CSV allowlist (default: nmap,httpx,nuclei,ffuf,gobuster,nikto)
  HEXSTRIKE_ALLOW_GENERIC        "true" to also expose run_tool() for allowlisted
                                 names that have no typed wrapper (default: false)
  HEXSTRIKE_TIMEOUT              per-call timeout in seconds (default 300)
  GATEWAY_HOST / GATEWAY_PORT    bind address (default 0.0.0.0:8888)
"""

import logging
import os
from typing import Any, Dict

import requests
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s [gateway] %(levelname)s %(message)s")
log = logging.getLogger("hexstrike-gateway")

HEXSTRIKE_URL = os.environ.get("HEXSTRIKE_URL", "http://hexstrike:8888").rstrip("/")
TIMEOUT = int(os.environ.get("HEXSTRIKE_TIMEOUT", "300"))
HOST = os.environ.get("GATEWAY_HOST", "0.0.0.0")
PORT = int(os.environ.get("GATEWAY_PORT", "8888"))

# Complementary to SHASEC: HexStrike fills the gaps SHASEC does not cover
# (deep exploitation, mass scanning, auth attacks). Pure duplicates of SHASEC
# plugins (httpx/nuclei/ffuf/nikto/katana/subfinder/whatweb/zap/...) are left
# to SHASEC and kept off this allowlist. nmap stays as the shared foundation.
DEFAULT_ALLOW = "nmap,amass,masscan,sqlmap,wpscan,dalfox,arjun,wafw00f,dotdotpwn,hydra"
ALLOWED = {t.strip().lower() for t in os.environ.get("HEXSTRIKE_ALLOWED_TOOLS", DEFAULT_ALLOW).split(",") if t.strip()}
ALLOW_GENERIC = os.environ.get("HEXSTRIKE_ALLOW_GENERIC", "false").strip().lower() in ("1", "true", "yes", "on")

_session = requests.Session()


def _forward(tool: str, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST a tool invocation to the HexStrike API and normalise the response.

    Enforces the allowlist one more time at call time (defence in depth: even a
    mis-registered tool cannot reach a non-allowlisted endpoint)."""
    if tool.lower() not in ALLOWED:
        return {"success": False, "error": f"tool '{tool}' is not in the gateway allowlist", "allowed": sorted(ALLOWED)}
    url = f"{HEXSTRIKE_URL}/{endpoint.lstrip('/')}"
    try:
        resp = _session.post(url, json=payload, timeout=TIMEOUT)
    except requests.RequestException as exc:
        log.error("forward to %s failed: %s", url, exc)
        return {"success": False, "error": f"gateway could not reach HexStrike: {exc}"}
    try:
        data = resp.json()
        if not isinstance(data, dict):
            data = {"result": data}
    except ValueError:
        data = {"raw_output": resp.text}
    data.setdefault("success", resp.ok)
    data["_gateway"] = {"tool": tool, "endpoint": endpoint, "http_status": resp.status_code}
    return data


# ---------------------------------------------------------------------------
# Typed tool wrappers. Parameter names mirror the HexStrike /api/tools/* bodies
# so the forwarded payload is exactly what the server expects.
# ---------------------------------------------------------------------------

def nmap(target: str, scan_type: str = "-sCV", ports: str = "", additional_args: str = "-T4 -Pn") -> Dict[str, Any]:
    """Nmap port/service scan against a lab target (host or IP).

    Args:
        target: host/IP to scan (required).
        scan_type: nmap scan flags, e.g. "-sCV", "-sS", "-sn".
        ports: port spec, e.g. "80,443" or "1-1000" (empty = nmap default).
        additional_args: extra nmap flags.
    """
    return _forward("nmap", "api/tools/nmap", {
        "target": target, "scan_type": scan_type, "ports": ports, "additional_args": additional_args,
    })


def httpx(target: str, tech_detect: bool = True, status_code: bool = True, title: bool = True,
          web_server: bool = True, threads: int = 50, additional_args: str = "") -> Dict[str, Any]:
    """Probe HTTP(S) endpoints with httpx (status, title, tech, server).

    Args:
        target: a URL/host, or a file path on the HexStrike container holding a list.
        tech_detect/status_code/title/web_server: toggle the matching httpx flags.
        threads: concurrency.
        additional_args: extra httpx flags.
    """
    return _forward("httpx", "api/tools/httpx", {
        "target": target, "probe": True, "tech_detect": tech_detect, "status_code": status_code,
        "title": title, "web_server": web_server, "threads": threads, "additional_args": additional_args,
    })


def nuclei(target: str, severity: str = "", tags: str = "", template: str = "",
           additional_args: str = "") -> Dict[str, Any]:
    """Run Nuclei templated vulnerability checks against a target URL.

    Args:
        target: target URL (required).
        severity: comma list, e.g. "low,medium,high,critical".
        tags: comma list of template tags.
        template: specific template path/id.
        additional_args: extra nuclei flags.
    """
    return _forward("nuclei", "api/tools/nuclei", {
        "target": target, "severity": severity, "tags": tags, "template": template,
        "additional_args": additional_args,
    })


def ffuf(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", mode: str = "directory",
         match_codes: str = "200,204,301,302,307,401,403", additional_args: str = "") -> Dict[str, Any]:
    """Fuzz a web target with ffuf. The ``FUZZ`` keyword is injected per mode.

    Args:
        url: base URL (required).
        wordlist: path to a wordlist on the HexStrike container.
        mode: "directory", "vhost", "parameter", or "raw".
        match_codes: HTTP codes to treat as hits.
        additional_args: extra ffuf flags.
    """
    return _forward("ffuf", "api/tools/ffuf", {
        "url": url, "wordlist": wordlist, "mode": mode, "match_codes": match_codes,
        "additional_args": additional_args,
    })


def gobuster(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt",
             additional_args: str = "") -> Dict[str, Any]:
    """Content/DNS/vhost discovery with gobuster.

    Args:
        url: target URL or domain (required).
        mode: one of "dir", "dns", "fuzz", "vhost".
        wordlist: path to a wordlist on the HexStrike container.
        additional_args: extra gobuster flags.
    """
    return _forward("gobuster", "api/tools/gobuster", {
        "url": url, "mode": mode, "wordlist": wordlist, "additional_args": additional_args,
    })


def nikto(target: str, additional_args: str = "") -> Dict[str, Any]:
    """Run a Nikto web server scan against a target URL/host.

    Args:
        target: target URL or host (required).
        additional_args: extra nikto flags.
    """
    return _forward("nikto", "api/tools/nikto", {"target": target, "additional_args": additional_args})


# --- Complementary tools (gaps SHASEC does not cover) ----------------------

def amass(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
    """Deep asset/subdomain discovery with amass (broader than SHASEC subfinder).

    Args:
        domain: root domain (required). mode: "enum" or "intel". additional_args: extra flags.
    """
    return _forward("amass", "api/tools/amass", {"domain": domain, "mode": mode, "additional_args": additional_args})


def masscan(target: str, ports: str = "1-65535", rate: int = 1000, additional_args: str = "") -> Dict[str, Any]:
    """Internet-scale fast port sweep with masscan (wide ranges SHASEC's nmap won't cover).

    Args:
        target: host/CIDR (required). ports: port spec. rate: packets/sec. additional_args: extra flags.
    """
    return _forward("masscan", "api/tools/masscan", {"target": target, "ports": ports, "rate": rate, "additional_args": additional_args})


def sqlmap(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
    """Deep SQL injection exploitation/dumping with sqlmap (SHASEC only detects SQLi).

    Args:
        url: target URL (required). data: POST body for form/JSON injection. additional_args: extra flags (e.g. --batch --level 3).
    """
    return _forward("sqlmap", "api/tools/sqlmap", {"url": url, "data": data, "additional_args": additional_args})


def wpscan(url: str, additional_args: str = "") -> Dict[str, Any]:
    """WordPress-specific enumeration/vuln scan with wpscan (no SHASEC equivalent).

    Args:
        url: WordPress site URL (required). additional_args: extra flags (e.g. --enumerate vp,u).
    """
    return _forward("wpscan", "api/tools/wpscan", {"url": url, "additional_args": additional_args})


def dalfox(url: str, blind: bool = False, custom_payload: str = "", additional_args: str = "") -> Dict[str, Any]:
    """Advanced XSS discovery + exploitation with dalfox (SHASEC's xss verifier only detects).

    Args:
        url: target URL (required). blind: enable blind-XSS mode. custom_payload: extra payload. additional_args: extra flags.
    """
    return _forward("dalfox", "api/tools/dalfox", {"url": url, "blind": blind, "custom_payload": custom_payload, "additional_args": additional_args})


def arjun(url: str, method: str = "GET", wordlist: str = "", threads: int = 25, additional_args: str = "") -> Dict[str, Any]:
    """Hidden HTTP parameter discovery with arjun (feeds other tools; no SHASEC equivalent).

    Args:
        url: target URL (required). method: HTTP method. wordlist: param wordlist path. threads: concurrency. additional_args: extra flags.
    """
    return _forward("arjun", "api/tools/arjun", {"url": url, "method": method, "wordlist": wordlist, "threads": threads, "additional_args": additional_args})


def wafw00f(target: str, additional_args: str = "") -> Dict[str, Any]:
    """Fingerprint the Web Application Firewall in front of a target with wafw00f.

    Args:
        target: URL/host (required). additional_args: extra flags.
    """
    return _forward("wafw00f", "api/tools/wafw00f", {"target": target, "additional_args": additional_args})


def dotdotpwn(target: str, module: str = "http", additional_args: str = "") -> Dict[str, Any]:
    """Directory/path traversal fuzzing with dotdotpwn (no SHASEC equivalent).

    Args:
        target: target host/URL (required). module: "http","http-url","ftp",... additional_args: extra flags.
    """
    return _forward("dotdotpwn", "api/tools/dotdotpwn", {"target": target, "module": module, "additional_args": additional_args})


def hydra(target: str, service: str = "", username: str = "", username_file: str = "",
          password: str = "", password_file: str = "", additional_args: str = "") -> Dict[str, Any]:
    """Online credential brute-forcing with hydra (SHASEC has no auth-attack capability).

    Args:
        target: host (required). service: e.g. "ssh","http-post-form","ftp". username/username_file and
        password/password_file: single value or wordlist path. additional_args: extra flags.
    """
    return _forward("hydra", "api/tools/hydra", {"target": target, "service": service, "username": username,
                    "username_file": username_file, "password": password, "password_file": password_file,
                    "additional_args": additional_args})


# Registry of everything the gateway KNOWS how to expose. Membership here is a
# precondition; the allowlist decides what is actually registered. The duplicate
# wrappers (httpx/nuclei/ffuf/gobuster/nikto) remain defined above but are left
# OUT of the registry so SHASEC owns that surface; re-add a line to expose one.
REGISTRY = {
    # shared foundation
    "nmap": (nmap, "Nmap port/service scan (advanced NSE beyond SHASEC's basic nmap)"),
    # recon breadth SHASEC lacks
    "amass": (amass, "amass deep asset/subdomain discovery"),
    "masscan": (masscan, "masscan internet-scale fast port sweep"),
    # deep offensive web SHASEC lacks (detection-only there)
    "sqlmap": (sqlmap, "sqlmap deep SQLi exploitation/dumping"),
    "wpscan": (wpscan, "WordPress enumeration/vuln scan"),
    "dalfox": (dalfox, "dalfox XSS discovery + exploitation"),
    "arjun": (arjun, "arjun hidden HTTP parameter discovery"),
    "wafw00f": (wafw00f, "wafw00f WAF fingerprinting"),
    "dotdotpwn": (dotdotpwn, "dotdotpwn path-traversal fuzzing"),
    # auth attacks SHASEC lacks
    "hydra": (hydra, "hydra online credential brute-forcing"),
}


def build_server() -> FastMCP:
    mcp = FastMCP("hexstrike-gateway", host=HOST, port=PORT)

    exposed = []
    for name, (fn, desc) in REGISTRY.items():
        if name in ALLOWED:
            mcp.add_tool(fn, name=name, description=desc)
            exposed.append(name)

    # Allowlisted names we have no typed wrapper for.
    unmapped = sorted(ALLOWED - set(REGISTRY))

    if ALLOW_GENERIC and unmapped:
        def run_tool(tool: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
            """Generic passthrough for allowlisted tools without a typed wrapper.

            Only tools present in the gateway allowlist are permitted, and only
            the ``/api/tools/<tool>`` surface is reachable — arbitrary command,
            python, file and payload endpoints are never exposed.

            Args:
                tool: the HexStrike tool name (must be in the allowlist).
                params: JSON body forwarded verbatim to /api/tools/<tool>.
            """
            if tool.lower() not in ALLOWED:
                return {"success": False, "error": f"tool '{tool}' not in allowlist", "allowed": sorted(ALLOWED)}
            return _forward(tool, f"api/tools/{tool}", params or {})
        mcp.add_tool(run_tool, name="run_tool",
                     description=f"Generic passthrough, restricted to allowlisted tools: {', '.join(unmapped)}")
        exposed.append("run_tool")
    elif unmapped:
        log.warning("allowlisted but not exposed (no typed wrapper; set HEXSTRIKE_ALLOW_GENERIC=true to enable): %s",
                    ", ".join(unmapped))

    def hexstrike_health() -> Dict[str, Any]:
        """Report whether the upstream HexStrike server is reachable and healthy."""
        try:
            r = _session.get(f"{HEXSTRIKE_URL}/health", timeout=10)
            out = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"raw": r.text}
            out["_gateway"] = {"upstream": HEXSTRIKE_URL, "http_status": r.status_code}
            return out
        except requests.RequestException as exc:
            return {"success": False, "error": f"cannot reach HexStrike at {HEXSTRIKE_URL}: {exc}"}

    def list_allowed_tools() -> Dict[str, Any]:
        """List the tools this gateway is configured to expose to the client."""
        return {"allowlist": sorted(ALLOWED), "exposed": sorted(exposed),
                "generic_passthrough": ALLOW_GENERIC, "upstream": HEXSTRIKE_URL}

    mcp.add_tool(hexstrike_health, name="hexstrike_health", description="Upstream HexStrike health check")
    mcp.add_tool(list_allowed_tools, name="list_allowed_tools", description="Show the effective tool allowlist")

    log.info("upstream=%s", HEXSTRIKE_URL)
    log.info("allowlist=%s", sorted(ALLOWED))
    log.info("exposed tools=%s", sorted(exposed))
    return mcp


if __name__ == "__main__":
    build_server().run(transport="streamable-http")
