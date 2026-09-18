"""Identify cloud/CDN/SaaS hosting from hostnames (CNAME targets) and ASNs.

Pattern-based and offline. Results feed ``cloud_resource`` assets, hosting
attributes and shadow-IT highlighting.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CloudMatch:
    provider: str
    service: str
    kind: str  # cloud | cdn | saas | paas
    resource: str  # the matched hostname


# (regex on hostname, provider, service, kind). Order matters: most specific first.
_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"\.s3[.-]website[.-][a-z0-9-]+\.amazonaws\.com$"), "aws", "s3_website", "cloud"),
    (re.compile(r"(^|\.)s3([.-][a-z0-9-]+)?\.amazonaws\.com$"), "aws", "s3", "cloud"),
    (re.compile(r"\.cloudfront\.net$"), "aws", "cloudfront", "cdn"),
    (re.compile(r"\.elb\.amazonaws\.com$"), "aws", "elastic_load_balancer", "cloud"),
    (re.compile(r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com$"), "aws", "api_gateway", "cloud"),
    (re.compile(r"\.elasticbeanstalk\.com$"), "aws", "elastic_beanstalk", "paas"),
    (re.compile(r"\.awsapprunner\.com$"), "aws", "app_runner", "paas"),
    (re.compile(r"\.amplifyapp\.com$"), "aws", "amplify", "paas"),
    (re.compile(r"\.amazonaws\.com$"), "aws", "aws", "cloud"),
    (re.compile(r"\.azurewebsites\.net$"), "azure", "app_service", "paas"),
    (re.compile(r"\.blob\.core\.windows\.net$"), "azure", "blob_storage", "cloud"),
    (re.compile(r"\.(file|queue|table)\.core\.windows\.net$"), "azure", "storage", "cloud"),
    (re.compile(r"\.database\.windows\.net$"), "azure", "sql_database", "cloud"),
    (re.compile(r"\.cloudapp\.(azure\.com|net)$"), "azure", "virtual_machine", "cloud"),
    (re.compile(r"\.azureedge\.net$"), "azure", "cdn", "cdn"),
    (re.compile(r"\.azurefd\.net$"), "azure", "front_door", "cdn"),
    (re.compile(r"\.trafficmanager\.net$"), "azure", "traffic_manager", "cloud"),
    (re.compile(r"\.azurestaticapps\.net$"), "azure", "static_web_apps", "paas"),
    (re.compile(r"\.azure-api\.net$"), "azure", "api_management", "cloud"),
    (re.compile(r"\.storage\.googleapis\.com$"), "gcp", "cloud_storage", "cloud"),
    (re.compile(r"\.appspot\.com$"), "gcp", "app_engine", "paas"),
    (re.compile(r"\.run\.app$"), "gcp", "cloud_run", "paas"),
    (re.compile(r"\.cloudfunctions\.net$"), "gcp", "cloud_functions", "paas"),
    (re.compile(r"\.(firebaseapp\.com|web\.app)$"), "gcp", "firebase_hosting", "paas"),
    (re.compile(r"\.oraclecloud\.com$"), "oci", "oracle_cloud", "cloud"),
    (re.compile(r"\.oci\.customer-oci\.com$"), "oci", "oracle_cloud", "cloud"),
    (re.compile(r"\.herokuapp\.com$"), "heroku", "app", "paas"),
    (re.compile(r"\.github\.io$"), "github", "pages", "paas"),
    (re.compile(r"\.netlify\.(app|com)$"), "netlify", "site", "paas"),
    (re.compile(r"\.vercel\.app$"), "vercel", "app", "paas"),
    (re.compile(r"\.pages\.dev$"), "cloudflare", "pages", "paas"),
    (re.compile(r"\.workers\.dev$"), "cloudflare", "workers", "paas"),
    (re.compile(r"\.cdn\.cloudflare\.net$"), "cloudflare", "cdn", "cdn"),
    (re.compile(r"\.(akamaiedge|akamaized|edgekey|edgesuite|akamaihd)\.net$"), "akamai", "cdn", "cdn"),
    (re.compile(r"\.fastly\.net$"), "fastly", "cdn", "cdn"),
    (re.compile(r"\.b-cdn\.net$"), "bunny", "cdn", "cdn"),
    (re.compile(r"\.myshopify\.com$"), "shopify", "store", "saas"),
    (re.compile(r"\.zendesk\.com$"), "zendesk", "helpdesk", "saas"),
    (re.compile(r"\.freshdesk\.com$"), "freshworks", "helpdesk", "saas"),
    (re.compile(r"\.wpengine\.com$"), "wpengine", "wordpress", "saas"),
    (re.compile(r"\.hubspot(pagebuilder)?\.(com|net)$"), "hubspot", "cms", "saas"),
    (re.compile(r"\.salesforce(-sites)?\.com$|\.force\.com$"), "salesforce", "sites", "saas"),
    (re.compile(r"\.sharepoint\.com$"), "microsoft", "sharepoint", "saas"),
]

# Well-known hosting/CDN networks by ASN (non-exhaustive, offline).
ASN_PROVIDERS: dict[int, tuple[str, str]] = {
    16509: ("aws", "cloud"), 14618: ("aws", "cloud"), 8987: ("aws", "cloud"),
    15169: ("gcp", "cloud"), 396982: ("gcp", "cloud"), 19527: ("gcp", "cloud"),
    8075: ("azure", "cloud"), 8068: ("azure", "cloud"),
    31898: ("oci", "cloud"),
    13335: ("cloudflare", "cdn"), 209242: ("cloudflare", "cdn"),
    20940: ("akamai", "cdn"), 16625: ("akamai", "cdn"), 63949: ("akamai", "cloud"),
    54113: ("fastly", "cdn"),
    14061: ("digitalocean", "cloud"), 24940: ("hetzner", "cloud"), 16276: ("ovh", "cloud"),
    20473: ("vultr", "cloud"), 36351: ("ibm", "cloud"),
    # Saudi Arabian carriers/hosting
    25019: ("stc", "isp"), 39891: ("stc", "isp"), 35819: ("mobily", "isp"), 43766: ("zain-sa", "isp"),
}

CDN_PROVIDERS = {"cloudflare", "akamai", "fastly", "bunny"}


def match_hostname(host: str) -> CloudMatch | None:
    for pattern, provider, service, kind in _PATTERNS:
        if pattern.search(host):
            return CloudMatch(provider, service, kind, host)
    return None


def provider_for_asn(asn: str | int | None) -> tuple[str, str] | None:
    if asn is None:
        return None
    try:
        n = int(str(asn).upper().removeprefix("AS"))
    except ValueError:
        return None
    return ASN_PROVIDERS.get(n)


def resource_value(m: CloudMatch) -> str:
    return f"{m.provider}:{m.service}:{m.resource}"
