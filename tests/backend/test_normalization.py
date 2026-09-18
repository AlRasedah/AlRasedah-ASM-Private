from __future__ import annotations

import pytest
from asm_sensors.observations import ObservedType

from app.assets import cloud
from app.assets.normalization import (
    classify_hostname,
    normalize_value,
    parent_domain,
    parse_port_value,
    registrable_domain,
)
from app.models.enums import AssetType


@pytest.mark.parametrize("t,raw,expected", [
    (ObservedType.HOSTNAME, "WWW.Example.COM.", "www.example.com"),
    (ObservedType.HOSTNAME, "-bad.example.com", None),
    (ObservedType.IP_ADDRESS, "2001:DB8:0::1", "2001:db8::1"),
    (ObservedType.IP_ADDRESS, "999.1.1.1", None),
    (ObservedType.CIDR, "192.0.2.7/24", "192.0.2.0/24"),
    (ObservedType.ASN, "as13335", "AS13335"),
    (ObservedType.PORT, "192.0.2.1:443/TCP", "192.0.2.1:443/tcp"),
    (ObservedType.PORT, "[2001:db8::1]:22/tcp", "[2001:db8::1]:22/tcp"),
    (ObservedType.PORT, "192.0.2.1:70000/tcp", None),
    (ObservedType.HTTP_ENDPOINT, "https://API.example.com:443/path?q=1", "https://api.example.com"),
    (ObservedType.HTTP_ENDPOINT, "http://example.com:8080", "http://example.com:8080"),
    (ObservedType.TECHNOLOGY, "  Microsoft   IIS ", "microsoft iis"),
    (ObservedType.CERTIFICATE, "AB:CD:EF:01:23", "abcdef0123"),
    (ObservedType.CERTIFICATE, "not-hex", None),
])
def test_normalize(t, raw, expected):
    assert normalize_value(t, raw) == expected


def test_registrable_domain_is_offline_and_psl_aware():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("portal.moh.gov.sa") == "moh.gov.sa"
    assert registrable_domain("www.example.com.sa") == "example.com.sa"


def test_classification():
    roots = {"example.com"}
    assert classify_hostname("example.com", roots) == AssetType.ROOT_DOMAIN
    assert classify_hostname("api.example.com", roots) == AssetType.SUBDOMAIN
    assert classify_hostname("example.net", roots) == AssetType.DOMAIN
    assert parent_domain("a.b.example.com", {"example.com", "b.example.com"}) == "b.example.com"
    assert parse_port_value("192.0.2.1:8443/tcp") == ("192.0.2.1", 8443, "tcp")


def test_cloud_detection():
    m = cloud.match_hostname("d111111abcdef8.cloudfront.net")
    assert m and (m.provider, m.service, m.kind) == ("aws", "cloudfront", "cdn")
    assert cloud.match_hostname("mybucket.s3.amazonaws.com").service == "s3"
    assert cloud.match_hostname("app.azurewebsites.net").provider == "azure"
    assert cloud.match_hostname("objectstorage.me-riyadh-1.oraclecloud.com").provider == "oci"
    assert cloud.match_hostname("www.example.com") is None
    assert cloud.provider_for_asn("AS13335") == ("cloudflare", "cdn")
    assert cloud.provider_for_asn(25019)[0] == "stc"
