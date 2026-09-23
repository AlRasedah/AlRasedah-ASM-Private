"""Descriptions of the data-source credentials a tenant can store.

One place, used by the API (and therefore the UI and the user guide), so a
provider can never appear in the interface as a bare tool name again. Each entry
says what the key buys, what format it has, and whether it needs a paid account.

``group`` sorts them into what they actually do:

* ``certificates``  – certificate transparency logs (new names appear the moment
  a TLS certificate is issued)
* ``dns``           – passive DNS / WHOIS history
* ``scan``          – internet-wide scan databases (what is exposed, where)
* ``code``          – code and leak search (hostnames leaked in repositories)
* ``dataset``       – curated subdomain datasets
* ``regional``      – engines whose coverage is mainly China-hosted assets
* ``scanner``       – not a data source: credentials a scanner uses
"""

from __future__ import annotations

from typing import Any

# provider -> (group, label, description, key format, paid?, signup URL)
PROVIDERS: dict[str, dict[str, Any]] = {
    "alienvault": {"group": "dns", "label": "AlienVault OTX",
                   "description": "Community threat intelligence with passive DNS for a domain.",
                   "key_format": "API key", "paid": False, "url": "https://otx.alienvault.com"},
    "binaryedge": {"group": "scan", "label": "BinaryEdge",
                   "description": "Internet-wide scan data. Check that your account's API is still active.",
                   "key_format": "API key", "paid": True, "url": "https://www.binaryedge.io"},
    "bufferover": {"group": "dataset", "label": "BufferOver",
                   "description": "DNS datasets built from internet-wide scans.",
                   "key_format": "API key", "paid": True, "url": "https://tls.bufferover.run"},
    "c99": {"group": "dataset", "label": "C99", "description": "Commercial subdomain finder API.",
            "key_format": "API key", "paid": True, "url": "https://api.c99.nl"},
    "censys": {"group": "certificates", "label": "Censys",
               "description": "Certificate and host search across the internet.",
               "key_format": "API_ID:SECRET", "paid": True, "url": "https://search.censys.io/account/api"},
    "certspotter": {"group": "certificates", "label": "Cert Spotter",
                    "description": "Certificate transparency monitoring: names appear as certificates are issued.",
                    "key_format": "API key", "paid": False, "url": "https://sslmate.com/certspotter"},
    "chaos": {"group": "dataset", "label": "Chaos (ProjectDiscovery)",
              "description": "ProjectDiscovery's dataset of known subdomains.",
              "key_format": "API key", "paid": False, "url": "https://cloud.projectdiscovery.io"},
    "chinaz": {"group": "regional", "label": "Chinaz",
               "description": "Chinese domain and DNS data service.", "key_format": "API key", "paid": True,
               "url": "https://apidata.chinaz.com"},
    "dnsdb": {"group": "dns", "label": "DNSDB (Farsight/DomainTools)",
              "description": "Large commercial passive-DNS history.", "key_format": "API key", "paid": True,
              "url": "https://www.domaintools.com/products/farsight-dnsdb/"},
    "dnsrepo": {"group": "dns", "label": "DNSRepo", "description": "Passive DNS dataset.",
                "key_format": "API key", "paid": True, "url": "https://dnsrepo.noc.org"},
    "facebook": {"group": "certificates", "label": "Facebook CT search",
                 "description": "Discontinued by Meta; kept only so an existing key can be removed.",
                 "key_format": "APP_ID:APP_SECRET", "paid": False, "url": None},
    "fofa": {"group": "regional", "label": "FOFA", "description": "Chinese internet-scan search engine.",
             "key_format": "email:API key", "paid": True, "url": "https://fofa.info"},
    "fullhunt": {"group": "scan", "label": "FullHunt", "description": "Attack-surface database of hosts and subdomains.",
                 "key_format": "API key", "paid": False, "url": "https://fullhunt.io"},
    "github": {"group": "code", "label": "GitHub",
               "description": "Finds hostnames leaked in public code (configuration files, scripts).",
               "key_format": "Personal access token", "paid": False, "url": "https://github.com/settings/tokens"},
    "hunter": {"group": "regional", "label": "Hunter (Qianxin)",
               "description": "Chinese internet-scan engine. Not Hunter.io — that key will not work.",
               "key_format": "API key", "paid": True, "url": "https://hunter.qianxin.com"},
    "intelx": {"group": "code", "label": "Intelligence X",
               "description": "Leaks, pastes and DNS data.", "key_format": "HOST:API key (e.g. free.intelx.io:key)",
               "paid": True, "url": "https://intelx.io"},
    "leakix": {"group": "scan", "label": "LeakIX", "description": "Scan data focused on exposed services and leaks.",
               "key_format": "API key", "paid": False, "url": "https://leakix.net"},
    "netlas": {"group": "scan", "label": "Netlas", "description": "Internet scan and DNS data.",
               "key_format": "API key", "paid": False, "url": "https://netlas.io"},
    "quake": {"group": "regional", "label": "Quake (360)", "description": "Chinese internet-scan engine.",
              "key_format": "API key", "paid": True, "url": "https://quake.360.net"},
    "redhuntlabs": {"group": "dataset", "label": "RedHunt Labs",
                    "description": "Attack-surface subdomain dataset.", "key_format": "ENDPOINT:API key",
                    "paid": True, "url": "https://redhuntlabs.com"},
    "robtex": {"group": "dns", "label": "Robtex", "description": "DNS and IP relationship data.",
               "key_format": "API key", "paid": True, "url": "https://www.robtex.com"},
    "securitytrails": {"group": "dns", "label": "SecurityTrails",
                       "description": "Historical DNS and subdomain database. The free tier is small.",
                       "key_format": "API key", "paid": True, "url": "https://securitytrails.com"},
    "shodan": {"group": "scan", "label": "Shodan",
               "description": "Internet scan data. With a key, Exteriq also looks up every authorized IP "
                              "(open ports, service versions, certificates and reported CVEs) without touching "
                              "your hosts, and searches Shodan for subdomains.",
               "key_format": "API key", "paid": True, "url": "https://account.shodan.io"},
    "threatbook": {"group": "regional", "label": "ThreatBook", "description": "Chinese threat-intelligence platform.",
                   "key_format": "API key", "paid": True, "url": "https://threatbook.io"},
    "virustotal": {"group": "dataset", "label": "VirusTotal",
                   "description": "Domains and subdomains seen by VirusTotal. Free keys are heavily rate limited.",
                   "key_format": "API key", "paid": False, "url": "https://www.virustotal.com"},
    "whoisxmlapi": {"group": "dns", "label": "WhoisXML API", "description": "WHOIS and DNS data services.",
                    "key_format": "API key", "paid": True, "url": "https://whoisxmlapi.com"},
    "zoomeyeapi": {"group": "regional", "label": "ZoomEye", "description": "Chinese internet-scan engine.",
                   "key_format": "HOST:API key", "paid": True, "url": "https://www.zoomeye.org"},
    "zap_auth": {"group": "scanner", "label": "Web application login",
                 "description": "Not a data source: the session cookie or token the web application scanner uses "
                                "to test pages behind a login (e.g. PHPSESSID=…; security=low).",
                 "key_format": "Cookie or token value", "paid": False, "url": None},
}

GROUPS = {
    "certificates": "Certificate transparency",
    "dns": "DNS & WHOIS history",
    "scan": "Internet scan data",
    "code": "Code & leak search",
    "dataset": "Subdomain datasets",
    "regional": "Regional engines (mainly China)",
    "scanner": "Scanner credentials",
}

# Providers Exteriq itself queries directly (beyond passing them to subfinder).
NATIVE = {"shodan", "crtsh", "zap_auth"}

# Sources that cannot return results any more, whatever key you hold: the upstream
# service is gone. They stay listed here — and keep working if a key is already
# stored — but are never offered for configuration, because "key saved, no data" is
# the most expensive kind of integration to debug.
UNAVAILABLE: dict[str, str] = {
    "facebook": "Meta discontinued its certificate transparency API, so this source "
                "returns nothing regardless of the credential.",
}


def is_available(provider: str) -> bool:
    return provider not in UNAVAILABLE


def describe(provider: str) -> dict[str, Any]:
    meta = PROVIDERS.get(provider)
    if meta is None:
        return {"group": "dataset", "label": provider.replace("_", " ").title(), "description": "",
                "key_format": "API key", "paid": False, "url": None}
    return meta
