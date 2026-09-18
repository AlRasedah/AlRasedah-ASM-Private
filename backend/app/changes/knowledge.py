"""Security knowledge used by change detection, detection rules and risk scoring."""

from __future__ import annotations

from app.models.enums import Severity

# port -> (service label, severity when newly exposed to the internet)
RISKY_PORTS: dict[int, tuple[str, Severity]] = {
    21: ("FTP", Severity.MEDIUM),
    23: ("Telnet", Severity.HIGH),
    69: ("TFTP", Severity.HIGH),
    111: ("RPCbind", Severity.MEDIUM),
    135: ("Microsoft RPC", Severity.HIGH),
    139: ("NetBIOS", Severity.HIGH),
    161: ("SNMP", Severity.MEDIUM),
    389: ("LDAP", Severity.MEDIUM),
    445: ("SMB", Severity.HIGH),
    873: ("rsync", Severity.MEDIUM),
    1433: ("Microsoft SQL Server", Severity.HIGH),
    1521: ("Oracle Database", Severity.HIGH),
    1883: ("MQTT", Severity.MEDIUM),
    2049: ("NFS", Severity.HIGH),
    2375: ("Docker API (unencrypted)", Severity.CRITICAL),
    2379: ("etcd", Severity.HIGH),
    3268: ("LDAP Global Catalog", Severity.MEDIUM),
    3306: ("MySQL", Severity.HIGH),
    3389: ("Remote Desktop (RDP)", Severity.HIGH),
    4786: ("Cisco Smart Install", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    5601: ("Kibana", Severity.MEDIUM),
    5672: ("AMQP", Severity.MEDIUM),
    5900: ("VNC", Severity.HIGH),
    5901: ("VNC", Severity.HIGH),
    5984: ("CouchDB", Severity.HIGH),
    5985: ("WinRM", Severity.HIGH),
    5986: ("WinRM (TLS)", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    6443: ("Kubernetes API", Severity.MEDIUM),
    8161: ("ActiveMQ console", Severity.MEDIUM),
    9042: ("Cassandra", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
    9300: ("Elasticsearch transport", Severity.HIGH),
    10250: ("Kubelet API", Severity.HIGH),
    11211: ("Memcached", Severity.HIGH),
    15672: ("RabbitMQ management", Severity.MEDIUM),
    27017: ("MongoDB", Severity.HIGH),
    27018: ("MongoDB", Severity.HIGH),
    50070: ("Hadoop NameNode", Severity.HIGH),
}

WEB_PORTS = {80, 81, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9443}

WELL_KNOWN_SERVICES = {
    22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1194: "openvpn", 1723: "pptp", 500: "isakmp",
    5060: "sip", 5061: "sips", 8080: "http-alt", 8443: "https-alt",
}

# Lower-case substrings identifying administrative / remote-access interfaces.
MANAGEMENT_INTERFACES = {
    "jenkins": "Jenkins", "grafana": "Grafana", "kibana": "Kibana", "phpmyadmin": "phpMyAdmin",
    "cpanel": "cPanel", "webmin": "Webmin", "plesk": "Plesk", "vcenter": "VMware vCenter", "vmware esxi": "VMware ESXi",
    "fortigate": "FortiGate", "fortinet": "Fortinet", "fortiweb": "FortiWeb", "citrix": "Citrix",
    "netscaler": "Citrix NetScaler", "pulse secure": "Pulse Secure", "ivanti": "Ivanti", "globalprotect": "GlobalProtect",
    "palo alto": "Palo Alto", "sonicwall": "SonicWall", "cisco asa": "Cisco ASA", "big-ip": "F5 BIG-IP",
    "outlook web app": "Outlook Web App", "microsoft exchange": "Microsoft Exchange", "gitlab": "GitLab",
    "portainer": "Portainer", "rabbitmq": "RabbitMQ", "tomcat": "Apache Tomcat", "weblogic": "Oracle WebLogic",
    "jboss": "JBoss", "adminer": "Adminer", "solr": "Apache Solr", "zabbix": "Zabbix", "nagios": "Nagios",
    "pgadmin": "pgAdmin", "mongo express": "Mongo Express", "argocd": "Argo CD", "kubernetes dashboard": "Kubernetes Dashboard",
    "traefik": "Traefik dashboard", "splunk": "Splunk", "sophos": "Sophos", "checkpoint": "Check Point",
    "mikrotik": "MikroTik", "routeros": "MikroTik RouterOS", "ilo": "HPE iLO", "idrac": "Dell iDRAC",
    "synology": "Synology DSM", "qnap": "QNAP", "wordpress login": "WordPress login", "wp-admin": "WordPress admin",
}

API_DOC_TECH = {"swagger", "swagger-ui", "redoc", "graphql", "graphiql", "openapi"}

LOGIN_MARKERS = ("login", "log in", "sign in", "signin", "sso", "authentication", "تسجيل الدخول", "دخول")


def management_interface(*texts: str | None) -> str | None:
    blob = " ".join(t.lower() for t in texts if t)
    if not blob:
        return None
    for needle, label in MANAGEMENT_INTERFACES.items():
        if needle in blob:
            return label
    return None


def looks_like_login(title: str | None) -> bool:
    t = (title or "").lower()
    return any(m in t for m in LOGIN_MARKERS)


def port_exposure_severity(port: int) -> Severity:
    if port in RISKY_PORTS:
        return RISKY_PORTS[port][1]
    if port in WEB_PORTS:
        return Severity.LOW
    return Severity.MEDIUM


def service_label(port: int) -> str | None:
    if port in RISKY_PORTS:
        return RISKY_PORTS[port][0]
    return WELL_KNOWN_SERVICES.get(port)
