"""Scanner output parser/normalizer tests using recorded tool output (no network)."""

from __future__ import annotations

from asm_sensors.adapters.amass import AmassAdapter, AmassConfig, parse_amass_output
from asm_sensors.adapters.dnsx import DnsxAdapter, DnsxConfig
from asm_sensors.adapters.httpx import HttpxAdapter, HttpxConfig, endpoint_base, split_product
from asm_sensors.adapters.naabu import NaabuAdapter, NaabuConfig
from asm_sensors.adapters.nuclei import NucleiAdapter, NucleiConfig
from asm_sensors.adapters.subfinder import SubfinderAdapter, SubfinderConfig
from asm_sensors.adapters.zap import (
    AUTH_PROVIDER,
    ZapActiveAdapter,
    ZapActiveConfig,
    ZapSpiderAdapter,
    ZapSpiderConfig,
    _include_regex,
    _ZapClient,
    alert_to_finding,
    auth_secret,
    target_url,
)
from asm_sensors.base import ExecutionContext, RawOutput
from asm_sensors.observations import (
    FindingCategory,
    FindingCoverage,
    LivenessCoverage,
    RelationCoverage,
    Severity,
)

from .helpers import Obs, fixture_bytes, raw, t


async def normalize(adapter, fixture, targets, config):
    parsed = await adapter.parse_results(raw(fixture))
    return parsed, Obs(await adapter.normalize(parsed, targets, config))


class TestAmass:
    async def test_graph_output(self):
        parsed, o = await normalize(AmassAdapter(), "amass_v4.txt", [t("domain", "example.com")], AmassConfig())
        assert {"example.com", "www.example.com", "api.example.com", "vpn.example.com", "dev-api.example.com",
                "cdn.example.com", "d111111abcdef8.cloudfront.net", "ns1.dnsprovider.net",
                "mx.mailhost.net"} <= o.values("hostname")
        # reverse-DNS pseudo names are never reported as hostnames
        assert not any(v.endswith("in-addr.arpa") for v in o.values("hostname"))
        assert {"192.0.2.10", "192.0.2.20", "198.51.100.7", "2001:db8::7"} <= o.values("ip_address")
        assert ("vpn.example.com", "2001:db8::7") in o.rels("resolves_to")
        assert ("cdn.example.com", "d111111abcdef8.cloudfront.net") in o.rels("cname")
        assert ("example.com", "mx.mailhost.net") in o.rels("mx_record")
        assert o.values("cidr") == {"192.0.2.0/24"}
        assert o.asset("asn", "AS64500").attributes["organization"].startswith("EXAMPLE-NET")
        assert ("AS64500", "192.0.2.0/24") in o.rels("announces")
        # ip -> asn is derived from netblock containment + announcement
        assert ("192.0.2.20", "AS64500") in o.rels("belongs_to_asn")
        assert o.n.coverage == []  # passive discovery never vouches for absence

    async def test_legacy_json_output(self):
        _, o = await normalize(AmassAdapter(), "amass_v3.jsonl", [t("domain", "example.com")], AmassConfig())
        assert {"shop.example.com", "old.example.com"} <= o.values("hostname")
        assert o.asset("hostname", "shop.example.com").attributes["discovery_sources"] == ["CertSpotter", "Crtsh"]
        assert ("shop.example.com", "192.0.2.30") in o.rels("resolves_to")
        assert ("192.0.2.30", "AS64500") in o.rels("belongs_to_asn")

    def test_ansi_codes_are_stripped(self):
        line = b"\x1b[32mmail.example.com (FQDN) --> a_record --> 192.0.2.25 (IPAddress)\x1b[0m\n"
        recs = parse_amass_output(line)
        assert recs[0]["src"] == "mail.example.com"

    def test_argv_is_a_list_without_shell(self):
        cfg = AmassConfig(mode="active", brute_force=True, timeout_minutes=5)
        argv = AmassAdapter().build_argv("/bin/amass", "/w/t.txt", "/w/o.txt", "/w/db", cfg)
        assert argv[:4] == ["/bin/amass", "enum", "-df", "/w/t.txt"]
        assert "-active" in argv and "-brute" in argv
        assert AmassAdapter().is_active(cfg) and not AmassAdapter().is_active(AmassConfig())

    def test_brute_requires_active(self):
        import pytest
        with pytest.raises(ValueError):
            AmassConfig(brute_force=True)


class TestSubfinder:
    async def test_normalizes_and_drops_invalid(self):
        _, o = await normalize(SubfinderAdapter(), "subfinder.jsonl", [t("domain", "example.com")], SubfinderConfig())
        hosts = o.values("hostname")
        assert hosts == {"api.example.com", "dev-api.example.com", "staging.example.com", "vpn.example.com"}
        assert o.asset("hostname", "api.example.com").attributes["discovery_sources"] == ["alienvault", "crtsh"]


class TestDnsx:
    async def test_records_and_coverage(self):
        targets = [t("hostname", h) for h in
                   ("api.example.com", "vpn.example.com", "cdn.example.com", "example.com", "gone.example.com")]
        _, o = await normalize(DnsxAdapter(), "dnsx.jsonl", targets, DnsxConfig())
        assert "gone.example.com" not in o.values("hostname")  # NXDOMAIN -> not observed
        dns = o.asset("hostname", "vpn.example.com").attributes["dns"]
        assert dns["a"] == ["198.51.100.7"] and dns["aaaa"] == ["2001:db8::7"]
        assert o.asset("hostname", "example.com").attributes["dns"]["mx"] == ["mx.mailhost.net"]
        assert ("cdn.example.com", "d111111abcdef8.cloudfront.net") in o.rels("cname")
        assert {("cdn.example.com", "203.0.113.80"), ("cdn.example.com", "203.0.113.81")} <= o.rels("resolves_to")
        live = [c for c in o.n.coverage if isinstance(c, LivenessCoverage)]
        assert live and "gone.example.com" in live[0].values
        rel = [c for c in o.n.coverage if isinstance(c, RelationCoverage) and c.relation.value == "resolves_to"]
        assert rel and len(rel[0].parents) == 5

    def test_resolvers_must_be_ips(self):
        import pytest
        with pytest.raises(ValueError):
            DnsxConfig(resolvers=["1.1.1.1; rm -rf /"])


class TestNaabu:
    async def test_both_json_shapes(self):
        targets = [t("ip", "198.51.100.7"), t("ip", "192.0.2.20")]
        _, o = await normalize(NaabuAdapter(), "naabu.jsonl", targets, NaabuConfig(port_set="custom",
                                                                                     custom_ports="1-65535"))
        assert o.values("port") == {"198.51.100.7:443/tcp", "198.51.100.7:10443/tcp",
                                    "192.0.2.20:3389/tcp", "192.0.2.20:443/tcp"}
        assert ("192.0.2.20", "192.0.2.20:3389/tcp") in o.rels("has_port")
        cov = o.n.coverage[0]
        assert isinstance(cov, RelationCoverage)
        assert cov.constraints["port_spec"] == "1-65535"
        assert sorted(cov.parents) == ["192.0.2.20", "198.51.100.7"]

    def test_port_validation(self):
        import pytest
        with pytest.raises(ValueError):
            NaabuConfig(port_set="custom", custom_ports="80;id")
        with pytest.raises(ValueError):
            NaabuConfig(port_set="custom")
        argv = NaabuAdapter().build_argv("/bin/naabu", "t", "o", NaabuConfig(port_set="web"))
        assert argv[argv.index("-p") + 1].startswith("80,443")
        assert argv[argv.index("-s") + 1] == "c"


class TestHttpx:
    async def test_endpoints_services_tech_certs(self):
        targets = [t("host_port", "api.example.com:443"), t("host_port", "vpn.example.com:10443"),
                   t("ip", "192.0.2.10"), t("hostname", "cdn.example.com")]
        _, o = await normalize(HttpxAdapter(), "httpx.jsonl", targets, HttpxConfig())
        assert o.values("http_endpoint") == {"https://api.example.com", "https://vpn.example.com:10443",
                                             "http://192.0.2.10", "https://cdn.example.com"}
        api = o.asset("http_endpoint", "https://api.example.com")
        assert api.attributes["status_code"] == 200 and api.attributes["tls_version"] == "tls12"
        svc = o.asset("service", "192.0.2.20:443/tcp")
        assert svc.attributes["product"] == "nginx" and svc.attributes["version"] == "1.24.0"
        assert ("https://api.example.com", "nginx") in o.rels("uses_technology")
        nginx_rel = next(r for r in o.relations if r.relation.value == "uses_technology" and r.target.value == "nginx")
        assert nginx_rel.attributes["version"] == "1.24.0"
        cert = o.asset("certificate", "abcdef0123")
        assert cert.attributes["sans"] == ["api.example.com", "www.example.com"]
        assert ("https://vpn.example.com:10443", "99887766") in o.rels("presents_certificate")
        assert ("api.example.com", "https://api.example.com") in o.rels("serves")
        assert ("192.0.2.10", "http://192.0.2.10") in o.rels("serves")
        assert o.asset("ip_address", "203.0.113.80").attributes["cdn"] is True
        assert "https://down.example.com" not in o.values("http_endpoint")
        serves = [c for c in o.n.coverage if isinstance(c, RelationCoverage) and c.relation.value == "serves"]
        specs = {c.constraints["port_spec"] for c in serves}
        assert "443" in specs and "10443" in specs

    def test_helpers(self):
        assert split_product("nginx/1.25.3 (Ubuntu)") == ("nginx", "1.25.3")
        assert split_product("Apache") == ("apache", None)
        assert endpoint_base("https://Example.com:443/x?y=1")[0] == "https://example.com"
        assert endpoint_base("http://example.com:8080/")[0] == "http://example.com:8080"
        assert endpoint_base("ftp://example.com") is None


class TestNuclei:
    async def test_findings_and_tech(self):
        targets = [t("url", "https://api.example.com"), t("url", "https://vpn.example.com:10443")]
        cfg = NucleiConfig(severities=[Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])
        _, o = await normalize(NucleiAdapter(), "nuclei.jsonl", targets, cfg)
        by_rule = {f.rule_id: f for f in o.findings}
        cve = by_rule["CVE-2018-13379"]
        assert cve.severity == Severity.CRITICAL and cve.cve == ["CVE-2018-13379"]
        assert cve.cvss_score == 9.8 and cve.epss_score == 0.97
        assert cve.asset.value == "https://vpn.example.com:10443"
        assert cve.category.value == "vulnerability"
        assert by_rule["swagger-api"].category.value == "exposure"
        # network/ssl results resolve to the concrete ip:port when the IP is known
        assert by_rule["weak-cipher-suites:tls-1.0"].asset.value == "198.51.100.7:10443/tcp"
        assert by_rule["openssh-detect"].asset.value == "198.51.100.7:22/tcp"
        # tech-tagged info results become technology observations, not findings
        assert "tech-detect:swagger-ui" not in by_rule
        assert ("https://api.example.com", "swagger-ui") in o.rels("uses_technology")
        cov = [c for c in o.n.coverage if isinstance(c, FindingCoverage)][0]
        assert {a.value for a in cov.assets} == {"https://api.example.com", "https://vpn.example.com:10443"}

    def test_safe_defaults(self):
        cfg = NucleiConfig(exclude_tags=[])
        assert "dos" in cfg.exclude_tags  # can never be removed
        argv = NucleiAdapter().build_argv("/bin/nuclei", "t", "o", NucleiConfig(), None)
        assert "-ni" in argv and "-omit-raw" in argv
        assert "intrusive" in argv[argv.index("-etags") + 1]

    def test_rejects_injection_in_tags(self):
        import pytest
        with pytest.raises(ValueError):
            NucleiConfig(tags=["cve,-code"])
        with pytest.raises(ValueError):
            NucleiConfig(extra_args="-code")  # type: ignore[call-arg]


async def _zap_normalize(adapter, fixture, targets, config):
    import json
    records = json.loads(fixture_bytes(fixture))
    parsed = await adapter.parse_results(RawOutput(records=records))
    return Obs(await adapter.normalize(parsed, targets, config))


class TestZapSpider:
    async def test_crawl_endpoints_and_passive_findings(self):
        targets = [t("url", "https://app.example.com")]
        o = await _zap_normalize(ZapSpiderAdapter(), "zap_spider.json", targets, ZapSpiderConfig())
        # Every crawled URL becomes an endpoint (query strings collapse to the base);
        # sensors observe, the platform decides scope, so off-host URLs are still reported.
        assert "https://app.example.com" in o.values("http_endpoint")
        assert "https://evil.test/phishing" not in o.values("http_endpoint")  # normalized to base
        assert "https://evil.test" in o.values("http_endpoint")
        by_rule = {f.rule_id: f for f in o.findings}
        clickjack = by_rule["zap:10020-1"]
        assert clickjack.severity == Severity.MEDIUM
        assert clickjack.category == FindingCategory.MISCONFIGURATION
        assert clickjack.cwe == ["CWE-1021"]
        assert clickjack.asset.value == "https://app.example.com"
        assert by_rule["zap:10011"].severity == Severity.LOW  # cookie without secure flag
        assert by_rule["zap:10023"].category == FindingCategory.EXPOSURE  # info disclosure
        # Passive findings get finding coverage so a fixed header can auto-resolve.
        cov = [c for c in o.n.coverage if isinstance(c, FindingCoverage)]
        assert cov and any(a.value == "https://app.example.com" for a in cov[0].assets)

    async def test_passive_scan_off_means_no_coverage(self):
        o = await _zap_normalize(ZapSpiderAdapter(), "zap_spider.json", [t("url", "https://app.example.com")],
                                 ZapSpiderConfig(passive_scan=False))
        assert not [c for c in o.n.coverage if isinstance(c, FindingCoverage)]

    def test_target_url_derivation(self):
        assert target_url(t("url", "https://app.example.com/x")) == "https://app.example.com/x"
        assert target_url(t("host_port", "app.example.com:8443")) == "https://app.example.com:8443"
        assert target_url(t("host_port", "app.example.com:8080")) == "http://app.example.com:8080"
        assert target_url(t("hostname", "app.example.com")) == "http://app.example.com"


class TestZapActive:
    async def test_active_findings_and_coverage(self):
        targets = [t("url", "https://app.example.com/search"), t("url", "https://app.example.com/comment")]
        o = await _zap_normalize(ZapActiveAdapter(), "zap_active.json", targets, ZapActiveConfig())
        by_rule = {f.rule_id: f for f in o.findings}
        sqli = by_rule["zap:40018"]
        assert sqli.severity == Severity.HIGH and sqli.cwe == ["CWE-89"]
        assert sqli.category == FindingCategory.VULNERABILITY
        assert sqli.asset.value == "https://app.example.com"
        assert sqli.evidence["param"] == "q" and "OR '1'='1'" in sqli.evidence["attack"]
        assert by_rule["zap:40012-1"].category == FindingCategory.VULNERABILITY  # reflected XSS
        assert by_rule["zap:6"].cwe == ["CWE-22"]  # path traversal
        # ZAP High is the ceiling — it never becomes "critical".
        assert all(f.severity != Severity.CRITICAL for f in o.findings)
        # ftp:// alert is unmappable and dropped.
        assert not any(f.rule_id == "zap:99999" for f in o.findings)
        cov = [c for c in o.n.coverage if isinstance(c, FindingCoverage)]
        assert cov and {a.value for a in cov[0].assets} == {"https://app.example.com"}

    def test_alert_mapping_helper(self):
        assert alert_to_finding({"url": "ftp://x/y", "risk": "High"}, "zap_active") is None
        ref, finding = alert_to_finding(
            {"url": "https://a.example.com/p", "risk": "informational", "name": "X", "pluginId": "1"}, "zap_active")
        assert ref.value == "https://a.example.com" and finding.severity == Severity.INFO


class _FakeZap(_ZapClient):
    """A ZAP client whose HTTP layer is replaced: records API calls and serves canned responses."""

    def __init__(self):  # no HTTP client
        self.calls = []

    async def call(self, component, kind, action, params=None):
        self.calls.append((component, kind, action, params or {}))
        if action == "newContext":
            return {"contextId": "7"}
        if action == "scan":
            return {"scan": "1"}
        if action == "status":
            return {"status": "100"}
        if action == "results":
            return {"results": ["https://app.example.com/login"]}
        if action == "recordsToScan":
            return {"recordsToScan": "0"}
        if action == "alerts":
            return {"alerts": []}
        return {}

    def params(self, action):
        return [p for (_c, _k, a, p) in self.calls if a == action]

    @property
    def auth_added(self):
        return self.params("addRule")

    @property
    def auth_removed(self):
        return [p["description"] for p in self.params("removeRule")]


class TestZapAuth:
    def test_credential_provider_and_header_config(self):
        assert AUTH_PROVIDER == "zap_auth"
        assert ZapSpiderAdapter.credential_providers == ("zap_auth",)
        assert ZapActiveAdapter.credential_providers == ("zap_auth",)
        assert ZapSpiderConfig().auth_header_name == "Cookie"
        assert ZapActiveConfig(auth_header_name="Authorization").auth_header_name == "Authorization"
        import pytest
        with pytest.raises(ValueError):
            ZapActiveConfig(auth_header_name="Bad Header: x")  # header injection attempt rejected

    def test_auth_secret_extraction(self, tmp_path):
        def ctx(creds):
            return ExecutionContext(workdir=tmp_path, credentials=creds)
        assert auth_secret(ctx({AUTH_PROVIDER: ["PHPSESSID=abc; security=low"]})) == "PHPSESSID=abc; security=low"
        assert auth_secret(ctx({})) is None
        assert auth_secret(ctx({AUTH_PROVIDER: ["bad\r\nInjected: 1"]})) is None  # CRLF rejected

    async def test_spider_injects_and_removes_scoped_auth_header(self, tmp_path):
        zap = _FakeZap()
        raw = RawOutput()
        cookie = "PHPSESSID=abc; security=low"
        await ZapSpiderAdapter()._crawl_one(zap, "https://app.example.com", ZapSpiderConfig(), raw,
                                            "asm-crawl-0", auth=cookie)
        assert len(zap.auth_added) == 1
        rule = zap.auth_added[0]
        assert rule["matchString"] == "Cookie" and rule["replacement"] == cookie
        assert rule["url"] == _include_regex("https://app.example.com")  # scoped to exactly the origin
        assert zap.auth_removed == [rule["description"]]  # cleaned up afterwards
        assert zap.params("removeContext") == [{"contextName": "asm-crawl-0"}]
        assert zap.params("accessUrl")[0]["followRedirects"] == "false"
        assert not raw.errors

    async def test_active_no_auth_when_no_credential(self, tmp_path):
        zap = _FakeZap()
        raw = RawOutput()
        await ZapActiveAdapter()._scan_origin(zap, "https://app.example.com", ["https://app.example.com"],
                                              ZapActiveConfig(), raw, "asm-ascan-0", auth=None)
        assert zap.auth_added == [] and zap.auth_removed == []
        assert zap.params("scan")[0]["contextId"] == "7"  # the active scan is bound to the job's context


def test_fixture_loader():
    assert fixture_bytes("dnsx.jsonl").startswith(b"{")
