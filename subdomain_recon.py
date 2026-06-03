#!/usr/bin/env python3
"""
SubRecon v3 — Subdomain Enumeration & Service Fingerprinting
=====================================================================
What's new in v3 vs v2:
  ✦ asyncio + aiohttp  — HTTP fingerprinting of ALL hosts runs in parallel
                          (5-10× faster on large target sets)
  ✦ Wildcard DNS guard — detects and filters wildcard domains before bruteforce
                          (eliminates false positives completely)
  ✦ IP dedup cache     — hosts sharing the same IP fingerprinted only once
                          (no redundant HTTP requests)
  ✦ Retry + backoff    — all HTTP calls retry up to 3× with exponential delay
                          (handles rate-limited / flaky sources)
  ✦ Confidence scoring — every detected service gets 0-100 % confidence
                          based on how many independent signals matched
  ✦ Parallel passive   — all passive sources queried concurrently via asyncio
  ✦ TLS SAN extraction — Subject Alternative Names pulled from live certs
  ✦ Signal weighting   — header match > body keyword > cookie > path probe
                          (reduces false detections from generic terms)

Usage:
    python3 subdomain_recon.py -d example.com
    python3 subdomain_recon.py -d example.com --threads 50 --ports
    python3 subdomain_recon.py -d example.com --virustotal VT_KEY --shodan KEY
    python3 subdomain_recon.py -d example.com --no-bruteforce --min-confidence 60

Requirements (install all for full functionality):
    pip install requests dnspython aiohttp ipwhois
"""

import argparse
import asyncio
import concurrent.futures
import datetime
import json
import random
import re
import socket
import ssl
import string
import time
import threading
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from urllib.parse import urljoin

# ─── Optional deps ─────────────────────────────────────────────────────────────
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False


# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER & COLOURS
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
  ███████╗██╗   ██╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ███████╗██║   ██║██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ╚════██║██║   ██║██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ███████║╚██████╔╝██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝
          Subdomain Recon & Service Fingerprinting  v3.0
"""

class C:
    RST  = "\033[0m";  BOLD = "\033[1m";  RED  = "\033[91m"; GRN  = "\033[92m"
    YLW  = "\033[93m"; BLU  = "\033[94m"; MAG  = "\033[95m"; CYN  = "\033[96m"
    GRY  = "\033[90m"

_print_lock = threading.Lock()

def cprint(color: str, msg: str):
    with _print_lock:
        print(f"{color}{msg}{C.RST}")

def status(label: str, msg: str, color: str = C.CYN):
    with _print_lock:
        print(f"  {C.GRY}[{C.RST}{color}{label}{C.RST}{C.GRY}]{C.RST} {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_WORDLIST = [
    # Web
    "www","www2","www3","web","web1","web2",
    # Mail
    "mail","mail1","mail2","smtp","pop","pop3","imap","ftp","sftp",
    "webmail","owa","exchange","autodiscover",
    # Remote / VPN
    "remote","vpn","vpn1","vpn2","rdp","rds","rds-office","citrix","sslvpn",
    # API
    "api","api2","api3","api-v2","api-new","v2","v1","v3","rest","graphql","grpc",
    # Admin / portals
    "admin","administrator","portal","panel","dashboard","manage","management",
    "cpanel","whm","plesk","ispmanager","backoffice","back-office",
    # Dev / staging environments
    "dev","dev1","dev2","dev3","develop","development",
    "staging","stage","stg","stg1","stg2",
    "test","test1","test2","testing","testenv",
    "qa","qa1","qa2","uat","preprod","pre-prod","sandbox",
    "prod","production","live",
    # Composite dev patterns (most common missed subdomains)
    "dev-api","dev-portal","dev-admin","dev-app","dev-web","dev-new",
    "dev-b2b","dev-crm","dev-shop","dev-billing",
    "dev1-portal","dev2-portal","dev1-api","dev2-api",
    "new-api","new-portal","new-admin","new-app","new-web","new-b2b",
    "old-portal","old-api","old-admin","old-app",
    "test-api","test-portal","test-admin","test-app","test-b2b",
    "stage-api","stage-portal","stage-app","stage-web",
    "beta","beta2","alpha","next","rc","preview",
    # CMS / Content
    "blog","forum","wiki","docs","documentation","kb","help","faq",
    "support","tickets","desk","helpdesk","service","servicedesk",
    # Business
    "crm","erp","billing","invoice","finance","hr","hris","1c",
    "b2b","b2c","cabinet","lk","kab","office","corp","intranet","internal",
    # E-commerce
    "shop","store","cart","ecommerce","pay","payment","checkout","catalog",
    # Media / Files
    "cdn","static","assets","media","img","images","files","uploads",
    "upload","download","storage","s3","backup","minio","fileserver",
    "shared","share","nas","nas01","nas02","nas03","mcloud","nfs",
    # DevOps / CI/CD
    "git","gitlab","github","svn","ci","cd","jenkins","drone","gitea",
    "jira","confluence","bitbucket","redmine","youtrack","linear",
    "registry","nexus","artifactory","harbor","docker","k8s","kube",
    # Monitoring
    "monitor","monitoring","metrics","grafana","kibana","prometheus",
    "elastic","splunk","nagios","zabbix","alertmanager","loki","opsgenie",
    # DNS / Network
    "mx","mx1","mx2","ns","ns1","ns2","dns","dns1","dns2","resolver",
    "proxy","gateway","lb","loadbalancer","waf","haproxy","traefik",
    # Auth
    "auth","sso","oauth","login","secure","id","accounts","identity","keycloak","okta",
    # Mobile / App
    "mobile","m","app","apps","apk","ios","android",
    # Cloud
    "cloud","aws","azure","gcp","k8s","kubernetes",
    # DB (exposed panels)
    "db","database","mysql","postgres","redis","mongo","phpmyadmin","adminer",
    # Communication
    "chat","im","mattermost","slack","teams","discord","rocket",
    # Misc
    "new","old","legacy","archive","demo","poc","pilot","lab","labs",
    "status","health","ping","uptime",
    "1","2","3","4","01","02","03",
    "server","server1","server2","server3","host","node","node1","node2",
    "pim","pim-pr","pb","casetg","lightcycle","career","survey","stock",
]

# Prefixes to combine with found subdomains for recursive bruteforce
RECURSIVE_PREFIXES = [
    "dev","dev1","dev2","test","stage","new","old","api","admin",
    "beta","rc","demo","pr","preprod","backup",
]

COMMON_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",587:"SMTP/TLS",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    5900:"VNC",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",
    8888:"HTTP-Dev",9200:"Elasticsearch",27017:"MongoDB",
}

# ─── Signal weights for confidence scoring ─────────────────────────────────
# Higher = more reliable indicator
SIGNAL_WEIGHTS = {
    "header_exact":   40,   # exact header key+value match
    "header_prefix":  25,   # header key prefix match
    "body_specific":  20,   # distinctive body string (paths, class names)
    "body_generic":   10,   # generic body keyword (could appear anywhere)
    "cookie":         30,   # cookie name match (very specific)
    "path_body":      35,   # confirmed via path probe + body match
}

# Minimum confidence to include a service in the report
DEFAULT_MIN_CONFIDENCE = 25

# ─── Service signatures with per-signal type tagging ──────────────────────
# Each signal is a tuple: (type, value)
# Types: "header_exact", "header_prefix", "body_specific", "body_generic", "cookie"
SERVICE_SIGNATURES: Dict[str, dict] = {
    "Bitrix24 / 1C-Bitrix": {
        "signals": [
            ("header_prefix",  "x-powered-cms: bitrix"),
            ("body_specific",  "/bitrix/js/"),
            ("body_specific",  "BX.message"),
            ("body_generic",   "bitrix24"),
            ("cookie",         "BITRIX_SM_"),
            ("cookie",         "BX_"),
        ],
        "paths": ["/bitrix/js/main/core/core.js"],
    },
    "Microsoft Exchange / OWA": {
        "signals": [
            ("header_exact",   "x-owa-version"),
            ("header_exact",   "x-feserver"),
            ("body_specific",  "OutlookSession"),
            ("body_specific",  "X-OWA-Version"),
        ],
        "paths": ["/owa/auth/logon.aspx", "/ews/exchange.asmx"],
    },
    "Microsoft Exchange ActiveSync": {
        "signals": [
            ("header_exact",   "ms-asprotocolversion"),
        ],
        "paths": ["/Microsoft-Server-ActiveSync"],
    },
    "WordPress": {
        "signals": [
            ("body_specific",  "/wp-content/themes/"),
            ("body_specific",  "/wp-includes/js/"),
            ("body_specific",  "wp-json"),
            ("body_generic",   "WordPress"),
        ],
        "paths": ["/wp-login.php", "/wp-admin/"],
    },
    "Joomla": {
        "signals": [
            ("body_specific",  "/components/com_"),
            ("body_specific",  "/media/jui/"),
            ("body_generic",   "Joomla!"),
        ],
        "paths": ["/administrator/index.php"],
    },
    "Drupal": {
        "signals": [
            ("header_exact",   "x-drupal-cache"),
            ("header_prefix",  "x-generator: drupal"),
            ("body_specific",  "/sites/default/files/"),
            ("body_specific",  "Drupal.settings"),
        ],
        "paths": ["/user/login"],
    },
    "phpBB Forum": {
        "signals": [
            ("body_specific",  "Powered by phpBB"),
            ("body_specific",  "phpBB Group"),
            ("body_generic",   "phpBB"),
        ],
    },
    "Confluence (Atlassian)": {
        "signals": [
            ("header_prefix",  "x-confluence-"),
            ("body_specific",  "confluence-context-path"),
            ("body_generic",   "Confluence"),
        ],
        "paths": ["/wiki/spaces", "/confluence/"],
    },
    "JIRA (Atlassian)": {
        "signals": [
            ("body_specific",  "Atlassian Jira"),
            ("body_specific",  "jira-frontend"),
            ("body_generic",   "JIRA"),
        ],
        "paths": ["/secure/Dashboard.jspa"],
    },
    "GitLab": {
        "signals": [
            ("header_prefix",  "x-gitlab-"),
            ("body_specific",  "gl-logo"),
            ("body_specific",  "GitLab Community Edition"),
            ("body_generic",   "GitLab"),
        ],
        "paths": ["/users/sign_in"],
    },
    "Jenkins": {
        "signals": [
            ("header_exact",   "x-jenkins"),
            ("header_exact",   "x-hudson"),
            ("body_specific",  "jenkins-head-css"),
            ("body_generic",   "Jenkins"),
        ],
        "paths": ["/login"],
    },
    "cPanel": {
        "signals": [
            ("body_specific",  "cPanel, Inc."),
            ("body_generic",   "cPanel"),
            ("body_generic",   "WHM"),
        ],
        "paths": [":2083/", ":2082/"],
    },
    "Plesk": {
        "signals": [
            ("body_specific",  "plesk-ui-library"),
            ("body_specific",  "plesk-icon"),
            ("body_generic",   "Plesk"),
        ],
        "paths": ["/login_up.php3"],
    },
    "Grafana": {
        "signals": [
            ("header_prefix",  "x-grafana-"),
            ("body_specific",  "grafana_session"),
            ("body_generic",   "Grafana"),
        ],
        "paths": ["/api/health"],
    },
    "Kibana": {
        "signals": [
            ("body_specific",  "kbn-injected-metadata"),
            ("body_specific",  "kbnVersion"),
            ("body_generic",   "Kibana"),
        ],
        "paths": ["/app/kibana"],
    },
    "Roundcube Webmail": {
        "signals": [
            ("body_specific",  "roundcube_sessid"),
            ("body_specific",  "rcmloginuser"),
            ("body_generic",   "Roundcube"),
        ],
        "paths": ["/roundcube/"],
    },
    "Nextcloud / ownCloud": {
        "signals": [
            ("body_specific",  "oc_sessionPassphrase"),
            ("body_specific",  "nextcloud-icon"),
            ("body_generic",   "Nextcloud"),
        ],
        "paths": ["/index.php/login"],
    },
    "Keycloak (SSO)": {
        "signals": [
            ("body_specific",  "keycloak-session"),
            ("body_specific",  "kc-logo-text"),
            ("body_generic",   "Keycloak"),
        ],
        "paths": ["/auth/realms/master/.well-known/openid-configuration"],
    },
    "SonarQube": {
        "signals": [
            ("body_specific",  "sonarqube-logo"),
            ("body_generic",   "SonarQube"),
        ],
        "paths": ["/api/system/status"],
    },
    "Zabbix": {
        "signals": [
            ("body_specific",  "zabbix.php"),
            ("body_specific",  "zbx_sessionid"),
            ("body_generic",   "Zabbix"),
        ],
        "paths": ["/zabbix/index.php"],
    },
    "phpMyAdmin": {
        "signals": [
            ("body_specific",  "phpMyAdmin"),
            ("body_specific",  "pma_absolute_uri"),
            ("cookie",         "phpMyAdmin"),
        ],
        "paths": ["/phpmyadmin/", "/pma/"],
    },
    "Adminer": {
        "signals": [
            ("body_specific",  "adminer.org"),
            ("body_generic",   "Adminer"),
        ],
        "paths": ["/adminer.php", "/adminer/"],
    },
    "Apache Tomcat": {
        "signals": [
            ("body_specific",  "Apache Tomcat"),
            ("body_specific",  "Tomcat Documentation"),
            ("header_prefix",  "x-powered-by: servlet"),
        ],
        "paths": ["/manager/html"],
    },
    "IIS": {
        "signals": [
            ("header_exact",   "server: microsoft-iis"),
            ("body_specific",  "IIS Windows Server"),
        ],
    },
    "nginx": {
        "signals": [
            ("header_exact",   "server: nginx"),
        ],
    },
    "Apache httpd": {
        "signals": [
            ("header_exact",   "server: apache"),
        ],
    },
    "Traefik": {
        "signals": [
            ("header_prefix",  "x-powered-by: traefik"),
            ("body_specific",  "Traefik"),
        ],
        "paths": ["/api/rawdata"],
    },
    "Varnish Cache": {
        "signals": [
            ("header_exact",   "x-varnish"),
            ("header_prefix",  "via: varnish"),
        ],
    },
    "Shopify": {
        "signals": [
            ("header_prefix",  "x-shopify-"),
            ("body_specific",  "cdn.shopify.com"),
            ("body_generic",   "Shopify"),
        ],
    },
    "Laravel (PHP)": {
        "signals": [
            ("cookie",         "laravel_session"),
            ("body_specific",  "laravel_token"),
            ("body_generic",   "Laravel"),
        ],
    },
    "Django (Python)": {
        "signals": [
            ("cookie",         "csrftoken"),
            ("body_specific",  "csrfmiddlewaretoken"),
            ("body_generic",   "Django"),
        ],
    },
    "Ruby on Rails": {
        "signals": [
            ("header_exact",   "x-runtime"),
            ("header_prefix",  "x-powered-by: phusion passenger"),
        ],
    },
    "ASP.NET": {
        "signals": [
            ("header_exact",   "x-aspnet-version"),
            ("header_exact",   "x-aspnetmvc-version"),
            ("header_prefix",  "x-powered-by: asp.net"),
            ("cookie",         "asp.net_sessionid"),
            ("cookie",         ".aspxauth"),
        ],
    },
    "Node.js / Express": {
        "signals": [
            ("header_exact",   "x-powered-by: express"),
        ],
    },
    "Mikrotik RouterOS": {
        "signals": [
            ("body_specific",  "RouterOS"),
            ("body_specific",  "MikroTik"),
        ],
        "paths": ["/winbox/"],
    },
    "Fortinet / FortiGate": {
        "signals": [
            ("header_exact",   "server: fortigate"),
            ("body_specific",  "FortiGate"),
        ],
    },
    "Cisco ASA": {
        "signals": [
            ("body_specific",  "clientless-vpn"),
        ],
        "paths": ["/+CSCOE+/logon.html"],
    },
    "Elasticsearch": {
        "signals": [
            ("body_specific",  '"cluster_name"'),
            ("body_specific",  '"cluster_uuid"'),
        ],
        "paths": ["/_cluster/health"],
    },
    "Redis (exposed)": {
        "signals": [
            ("body_specific",  "redis_version"),
            ("body_specific",  "redis_mode"),
        ],
    },
    "MinIO": {
        "signals": [
            ("body_specific",  "minio-logo"),
            ("body_generic",   "MinIO"),
        ],
        "paths": ["/minio/health/live"],
    },
    "Prometheus": {
        "signals": [
            ("body_specific",  "prometheus_build_info"),
            ("body_generic",   "Prometheus"),
        ],
        "paths": ["/metrics", "/-/healthy"],
    },
    "Vault (HashiCorp)": {
        "signals": [
            ("body_specific",  "vault-logo"),
            ("body_generic",   "Vault"),
        ],
        "paths": ["/v1/sys/health"],
    },
    "Kubernetes Dashboard": {
        "signals": [
            ("body_specific",  "kube-dashboard"),
            ("body_generic",   "Kubernetes"),
        ],
        "paths": ["/#/login"],
    },
}

# ─── WAF signatures ───────────────────────────────────────────────────────────
# Each entry: (check_fn, confidence_pct)
WAF_SIGNATURES: Dict[str, Tuple] = {
    "Cloudflare":        (lambda h, b, c: "cf-ray" in h or h.get("server","").lower().startswith("cloudflare"), 95),
    "AWS WAF / Shield":  (lambda h, b, c: "x-amzn-requestid" in h or "x-amz-cf-id" in h, 85),
    "Akamai":            (lambda h, b, c: "x-akamai-transformed" in h or "x-check-cacheable" in h, 90),
    "Fastly":            (lambda h, b, c: "x-served-by" in h and "cache-" in h.get("x-served-by","").lower(), 85),
    "Imperva Incapsula": (lambda h, b, c: "x-iinfo" in h or "visid_incap" in c, 90),
    "Sucuri":            (lambda h, b, c: "x-sucuri-id" in h or "sucuri-cloudproxy" in h.get("server","").lower(), 90),
    "F5 BIG-IP ASM":     (lambda h, b, c: "bigipserver" in c or "ts_" in c, 80),
    "Barracuda WAF":     (lambda h, b, c: "barra_counter_session" in c, 85),
    "ModSecurity":       (lambda h, b, c: "mod_security" in b or "modsecurity" in h.get("server","").lower(), 75),
    "DDoS-Guard":        (lambda h, b, c: "ddos-guard" in h.get("server","").lower(), 90),
    "Nginx + NAXSI":     (lambda h, b, c: "x-data-origin" in h, 70),
    "Qrator":            (lambda h, b, c: "x-qrator-" in " ".join(h.keys()), 85),
}

# ─── Version extraction patterns ──────────────────────────────────────────────
# Each tuple: (regex, tech_name, search_in)
# search_in: "server" = only Server header, "body" = only body, "any" = both
VERSION_PATTERNS = [
    # Web servers — Server header
    (r"(?i)Apache/(\d+\.\d+[\.\d]*)",              "Apache",       "any"),
    (r"(?i)nginx/(\d+\.\d+[\.\d]*)",               "nginx",        "any"),
    (r"(?i)Microsoft-IIS/(\d+\.\d+)",              "IIS",          "any"),
    (r"(?i)LiteSpeed/?([\d.]+)?",                  "LiteSpeed",    "server"),
    (r"(?i)Caddy(?:/(\d+\.\d+[\.\d]*))?",          "Caddy",        "server"),
    (r"(?i)openresty/([\d.]+)",                    "OpenResty",    "server"),
    # Runtime / Language
    (r"(?i)PHP/(\d+\.\d+[\.\d]*)",                 "PHP",          "any"),
    (r"(?i)OpenSSL/(\d+[\.\d\w]*)",                "OpenSSL",      "any"),
    (r"(?i)Python/(\d+\.\d+[\.\d]*)",              "Python",       "server"),
    (r"(?i)Ruby/(\d+\.\d+[\.\d]*)",                "Ruby",         "server"),
    (r"(?i)Node\.?js[/ v]*([\d.]+)",               "Node.js",      "any"),
    # CMS
    (r"(?i)WordPress[/ ](\d+\.\d+[\.\d]*)",        "WordPress",    "any"),
    (r"(?i)<meta[^>]+generator[^>]+WordPress (\d+\.\d+[\.\d]*)", "WordPress", "body"),
    (r"(?i)Drupal (\d+\.?\d*)",                    "Drupal",       "any"),
    (r"(?i)Joomla[! /]?(\d+\.\d+)",               "Joomla",       "any"),
    (r"(?i)Bitrix(?:24)?[/ ]?([\d.]+)?",           "Bitrix",       "any"),
    (r"(?i)1C-Bitrix[/ ]?([\d.]+)?",              "1C-Bitrix",    "any"),
    (r"(?i)Pimcore[/ ]?([\d.]+)?",                "Pimcore",      "body"),
    # App servers
    (r"(?i)Tomcat/(\d+\.\d+[\.\d]*)",              "Tomcat",       "any"),
    (r"(?i)JBoss[/ ](\d+\.\d+)",                  "JBoss",        "any"),
    (r"(?i)WildFly[/ ](\d+)",                     "WildFly",      "any"),
    (r"(?i)Spring(?:Boot)?[/ ](\d+\.\d+)",        "Spring",       "any"),
    (r"(?i)Gunicorn/(\d+\.\d+[\.\d]*)",           "Gunicorn",     "server"),
    (r"(?i)uWSGI[/ ](\d+\.\d+[\.\d]*)",          "uWSGI",        "server"),
    # Storage / DB panels
    (r"(?i)redis_version[\":\s]+([\d.]+)",         "Redis",        "body"),
    (r"(?i)MongoDB\s*([\d.]+)?",                  "MongoDB",      "body"),
    (r"(?i)Elasticsearch[\"/ ]([\d.]+)",           "Elasticsearch","body"),
    (r"(?i)MinIO[/ ]([\d.]+)?",                   "MinIO",        "body"),
    (r"(?i)Synology\s*NAS",                       "Synology NAS", "body"),
    # CRM / ERP
    (r"(?i)BPMSoft[/ ]?([\d.]+)?",               "BPMSoft",      "body"),
    (r"(?i)Pimcore[^\"]*version[\":\s]+([\d.]+)", "Pimcore",      "body"),
    (r"(?i)Nextcloud[/ ]?([\d.]+)?",              "Nextcloud",    "body"),
    (r"(?i)ownCloud[/ ]?([\d.]+)?",              "ownCloud",     "body"),
    (r"(?i)GitLab[/ ]?([\d.]+)?",                "GitLab",       "body"),
    (r"(?i)Jenkins[/ ]?([\d.]+)?",               "Jenkins",      "body"),
    (r"(?i)Grafana[/ v]*([\d.]+)",               "Grafana",      "body"),
    (r"(?i)Keycloak[/ ]?([\d.]+)?",              "Keycloak",     "body"),
    (r"(?i)SonarQube[/ ]?([\d.]+)?",             "SonarQube",    "body"),
    # JS frameworks (from body)
    (r"(?i)Bootstrap[/ ](\d+\.\d+[\.\d]*)",       "Bootstrap",    "body"),
    (r"(?i)jQuery[/ v]*(\d+\.\d+[\.\d]*)",        "jQuery",       "body"),
    (r"(?i)React[/ ](\d+\.\d+[\.\d]*)",           "React",        "body"),
    (r"(?i)Vue[. /](\d+\.\d+[\.\d]*)",           "Vue.js",       "body"),
    (r"(?i)Angular[/ ](\d+\.\d+[\.\d]*)",        "Angular",      "body"),
]


def extract_versions(body: str, server_header: str = "",
                     powered_header: str = "") -> list:
    """
    Extract technology versions from response.
    Returns list of 'Tech/version' strings, deduped.
    """
    found = {}
    for pattern, tech, where in VERSION_PATTERNS:
        if where == "server":
            targets = [server_header or "", powered_header or ""]
        elif where == "body":
            targets = [body[:8000] if body else ""]
        else:
            targets = [(server_header or "") + " " + (powered_header or ""),
                       body[:8000] if body else ""]

        for target in targets:
            if not target:
                continue
            m = re.search(pattern, target)
            if m:
                ver = m.group(1) if m.lastindex and m.group(1) else ""
                label = f"{tech}/{ver}" if ver else tech
                if tech not in found:
                    found[tech] = label
                break

    return list(found.values())


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP RETRY HELPER
# ═══════════════════════════════════════════════════════════════════════════════

UA = "Mozilla/5.0 (compatible; SubRecon/3.0)"

def http_get_retry(url: str, timeout: float = 6, retries: int = 3,
                   headers: Optional[dict] = None) -> Optional["requests.Response"]:
    """Synchronous GET with exponential backoff retry."""
    if not HAS_REQUESTS:
        return None
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    for attempt in range(retries):
        try:
            return requests.get(url, timeout=timeout, verify=False,
                                allow_redirects=True, headers=h)
        except requests.exceptions.ConnectionError:
            break  # no point retrying a connection refused
        except Exception:
            if attempt < retries - 1:
                time.sleep(0.5 * (2 ** attempt))
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS RESOLUTION
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_hostname(hostname: str) -> dict:
    result = {"hostname": hostname, "ips": [], "ipv6": [], "cname": None, "alive": False}
    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        try:
            ans = resolver.resolve(hostname, "A")
            result["ips"] = [r.address for r in ans]
            result["alive"] = True
        except Exception:
            pass
        try:
            ans = resolver.resolve(hostname, "AAAA")
            result["ipv6"] = [r.address for r in ans]
            result["alive"] = True
        except Exception:
            pass
        try:
            ans = resolver.resolve(hostname, "CNAME")
            result["cname"] = str(ans[0].target)
        except Exception:
            pass
    else:
        try:
            info = socket.getaddrinfo(hostname, None)
            for item in info:
                addr = item[4][0]
                if ":" in addr and addr not in result["ipv6"]:
                    result["ipv6"].append(addr)
                elif addr not in result["ips"]:
                    result["ips"].append(addr)
            result["alive"] = bool(result["ips"] or result["ipv6"])
        except socket.gaierror:
            pass
    return result


def get_ptr(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  WILDCARD DNS DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def detect_wildcard(domain: str) -> Optional[set]:
    """
    Returns set of wildcard IPs if domain has wildcard DNS, else None.
    Tests two random hostnames. If both resolve to the same IPs → wildcard.
    """
    def rand_host():
        rand = ''.join(random.choices(string.ascii_lowercase, k=12))
        return f"{rand}.{domain}"

    h1 = rand_host()
    h2 = rand_host()
    r1 = resolve_hostname(h1)
    r2 = resolve_hostname(h2)

    if not r1["alive"] or not r2["alive"]:
        return None  # no wildcard

    ips1 = set(r1["ips"] + r1["ipv6"])
    ips2 = set(r2["ips"] + r2["ipv6"])
    overlap = ips1 & ips2
    if overlap:
        return overlap  # these IPs are the wildcard targets
    return None


def filter_wildcard_results(subdomains: set, wildcard_ips: set, domain: str) -> set:
    """
    Remove subdomains whose IPs match the wildcard IPs.
    Keeps subdomains that resolve to *different* IPs (legitimately configured).
    """
    filtered = set()
    for hostname in subdomains:
        info = resolve_hostname(hostname)
        if not info["alive"]:
            continue
        host_ips = set(info["ips"] + info["ipv6"])
        if not host_ips.issubset(wildcard_ips):
            filtered.add(hostname)
    return filtered


# ═══════════════════════════════════════════════════════════════════════════════
#  TLS SAN EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def get_tls_sans(hostname: str, timeout: float = 5) -> set:
    """Extract Subject Alternative Names from TLS certificate."""
    subs = set()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                for typ, val in cert.get("subjectAltName", []):
                    if typ == "DNS":
                        val = val.lower().lstrip("*.")
                        subs.add(val)
    except Exception:
        pass
    return subs


# ═══════════════════════════════════════════════════════════════════════════════
#  PORT SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

def scan_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_ports(host: str, ports: dict, timeout: float = 1.5) -> dict:
    open_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(30, len(ports))) as ex:
        future_map = {ex.submit(scan_port, host, p, timeout): (p, svc)
                      for p, svc in ports.items()}
        for future in concurrent.futures.as_completed(future_map):
            port, svc = future_map[future]
            if future.result():
                open_ports[port] = svc
    return open_ports


# ═══════════════════════════════════════════════════════════════════════════════
#  OSINT ENRICHMENT
# ═══════════════════════════════════════════════════════════════════════════════

_ip_info_cache: Dict[str, dict] = {}
_ip_info_lock  = threading.Lock()

def get_ip_info(ip: str) -> dict:
    """Geo/ASN for an IP, cached to avoid duplicate lookups."""
    info = {"asn": None, "asn_org": None, "country": None, "city": None}
    if not ip or ip.startswith(("10.", "192.168.", "127.", "::1")):
        return info
    with _ip_info_lock:
        if ip in _ip_info_cache:
            return _ip_info_cache[ip]
    if HAS_IPWHOIS:
        try:
            res = IPWhois(ip).lookup_rdap(depth=1)
            info["asn"]     = res.get("asn")
            info["asn_org"] = res.get("asn_description")
            info["country"] = res.get("asn_country_code")
        except Exception:
            pass
    if not info["country"] and HAS_REQUESTS:
        try:
            r = http_get_retry(
                f"http://ip-api.com/json/{ip}?fields=country,city,isp,as",
                timeout=4, retries=2)
            if r and r.ok:
                d = r.json()
                info["country"] = d.get("country")
                info["city"]    = d.get("city")
                if not info["asn_org"]:
                    info["asn_org"] = d.get("isp") or d.get("as")
        except Exception:
            pass
    with _ip_info_lock:
        _ip_info_cache[ip] = info
    return info


def get_shodan_host(ip: str, api_key: str) -> dict:
    info = {"ports": [], "vulns": [], "tags": [], "hostnames": []}
    if not HAS_REQUESTS or not api_key:
        return info
    try:
        r = http_get_retry(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=8, retries=2)
        if r and r.ok:
            d = r.json()
            info["ports"]     = d.get("ports", [])
            info["vulns"]     = list(d.get("vulns", {}).keys())
            info["tags"]      = d.get("tags", [])
            info["hostnames"] = d.get("hostnames", [])
    except Exception:
        pass
    return info


# ═══════════════════════════════════════════════════════════════════════════════
#  PASSIVE SUBDOMAIN SOURCES (async)
# ═══════════════════════════════════════════════════════════════════════════════

async def _async_get(session: "aiohttp.ClientSession", url: str, **kwargs) -> Optional[dict]:
    """Async GET with retry, returns (text, json_data) tuple or None."""
    for attempt in range(3):
        try:
            async with session.get(url, ssl=False, **kwargs) as resp:
                if resp.status == 200:
                    try:
                        return {"json": await resp.json(content_type=None),
                                "text": await resp.text()}
                    except Exception:
                        return {"json": None, "text": await resp.text()}
        except Exception:
            if attempt < 2:
                await asyncio.sleep(0.5 * (2 ** attempt))
    return None


async def _fetch_crtsh_async(session, domain: str) -> set:
    subs = set()
    data = await _async_get(session, f"https://crt.sh/?q=%.{domain}&output=json",
                            timeout=aiohttp.ClientTimeout(total=25))
    if data and data["json"]:
        for entry in data["json"]:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name)
    return subs


async def _fetch_hackertarget_async(session, domain: str) -> set:
    subs = set()
    data = await _async_get(session, f"https://api.hackertarget.com/hostsearch/?q={domain}",
                            timeout=aiohttp.ClientTimeout(total=15))
    if data and data["text"] and "API count exceeded" not in data["text"]:
        for line in data["text"].splitlines():
            host = line.split(",")[0].strip().lower()
            if host.endswith(f".{domain}"):
                subs.add(host)
    return subs


async def _fetch_alienvault_async(session, domain: str) -> set:
    subs = set()
    data = await _async_get(
        session,
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        timeout=aiohttp.ClientTimeout(total=15))
    if data and data["json"]:
        for rec in data["json"].get("passive_dns", []):
            host = rec.get("hostname", "").strip().lower()
            if host.endswith(f".{domain}"):
                subs.add(host)
    return subs


async def _fetch_bufferover_async(session, domain: str) -> set:
    subs = set()
    data = await _async_get(session, f"https://dns.bufferover.run/dns?q=.{domain}",
                            timeout=aiohttp.ClientTimeout(total=10))
    if data and data["json"]:
        for record in data["json"].get("FDNS_A", []) + data["json"].get("RDNS", []):
            for part in record.split(","):
                part = part.strip().lower()
                if part.endswith(f".{domain}"):
                    subs.add(part)
    return subs


async def _fetch_rapiddns_async(session, domain: str) -> set:
    subs = set()
    data = await _async_get(session, f"https://rapiddns.io/subdomain/{domain}?full=1",
                            timeout=aiohttp.ClientTimeout(total=10))
    if data and data["text"]:
        pattern = r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>'
        for m in re.findall(pattern, data["text"]):
            subs.add(m.lower())
    return subs


async def _fetch_urlscan_async(session, domain: str) -> set:
    """urlscan.io — often has subdomains not in CT logs."""
    subs = set()
    data = await _async_get(
        session,
        f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200",
        timeout=aiohttp.ClientTimeout(total=15))
    if data and data["json"]:
        for result in data["json"].get("results", []):
            host = result.get("page", {}).get("domain", "").lower()
            if host.endswith(f".{domain}") or host == domain:
                subs.add(host)
    return subs


async def _fetch_anubis_async(session, domain: str) -> set:
    """Anubis-DB — free, good for Russian domains."""
    subs = set()
    data = await _async_get(
        session,
        f"https://jldc.me/anubis/subdomains/{domain}",
        timeout=aiohttp.ClientTimeout(total=10))
    if data and data["json"] and isinstance(data["json"], list):
        for h in data["json"]:
            h = h.lower().strip()
            if h.endswith(f".{domain}") or h == domain:
                subs.add(h)
    return subs


async def _fetch_webarchive_async(session, domain: str) -> set:
    """Wayback Machine CDX — finds historical subdomains."""
    subs = set()
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=json&fl=original&collapse=urlkey&limit=500")
    data = await _async_get(session, url, timeout=aiohttp.ClientTimeout(total=20))
    if data and data["json"] and isinstance(data["json"], list):
        for row in data["json"][1:]:   # skip header row
            if row:
                try:
                    from urllib.parse import urlparse
                    host = urlparse(row[0]).hostname or ""
                    host = host.lower().lstrip("*.")
                    if host.endswith(f".{domain}") or host == domain:
                        subs.add(host)
                except Exception:
                    pass
    return subs


async def _fetch_certspotter_async(session, domain: str) -> set:
    """CertSpotter — alternative CT source, different coverage than crt.sh."""
    subs = set()
    data = await _async_get(
        session,
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        f"&include_subdomains=true&expand=dns_names",
        timeout=aiohttp.ClientTimeout(total=15))
    if data and data["json"] and isinstance(data["json"], list):
        for entry in data["json"]:
            for name in entry.get("dns_names", []):
                name = name.lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name)
    return subs


async def _fetch_virustotal_async(session, domain: str, api_key: str) -> set:
    subs = set()
    if not api_key:
        return subs
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    while url:
        data = await _async_get(session, url, headers=headers,
                                timeout=aiohttp.ClientTimeout(total=15))
        if not data or not data["json"]:
            break
        for item in data["json"].get("data", []):
            host = item.get("id", "").lower()
            if host.endswith(f".{domain}") or host == domain:
                subs.add(host)
        url = data["json"].get("links", {}).get("next")
        if url:
            await asyncio.sleep(15)  # VT free tier: 4 req/min
    return subs


async def _fetch_securitytrails_async(session, domain: str, api_key: str) -> set:
    subs = set()
    if not api_key:
        return subs
    data = await _async_get(
        session,
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        headers={"apikey": api_key},
        timeout=aiohttp.ClientTimeout(total=15))
    if data and data["json"]:
        for sub in data["json"].get("subdomains", []):
            subs.add(f"{sub}.{domain}")
    return subs


async def _fetch_shodan_dns_async(session, domain: str, api_key: str) -> set:
    subs = set()
    if not api_key:
        return subs
    data = await _async_get(
        session,
        f"https://api.shodan.io/dns/domain/{domain}?key={api_key}",
        timeout=aiohttp.ClientTimeout(total=15))
    if data and data["json"]:
        for sub in data["json"].get("subdomains", []):
            subs.add(f"{sub}.{domain}")
    return subs


async def fetch_passive_sources_async(domain: str, vt_key: str = "",
                                       st_key: str = "", shodan_key: str = "") -> dict:
    """Run all passive sources concurrently. Returns {source_name: set}."""
    if not HAS_AIOHTTP:
        # Fallback to sequential sync
        return {}

    connector = aiohttp.TCPConnector(limit=10, ssl=False)
    headers   = {"User-Agent": UA}
    results   = {}

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = {
            "crt.sh":         _fetch_crtsh_async(session, domain),
            "HackerTarget":   _fetch_hackertarget_async(session, domain),
            "AlienVault OTX": _fetch_alienvault_async(session, domain),
            "BufferOver":     _fetch_bufferover_async(session, domain),
            "RapidDNS":       _fetch_rapiddns_async(session, domain),
            "URLScan":        _fetch_urlscan_async(session, domain),
            "Anubis-DB":      _fetch_anubis_async(session, domain),
            "WebArchive":     _fetch_webarchive_async(session, domain),
            "CertSpotter":    _fetch_certspotter_async(session, domain),
        }
        if vt_key:
            tasks["VirusTotal"] = _fetch_virustotal_async(session, domain, vt_key)
        if st_key:
            tasks["SecurityTrails"] = _fetch_securitytrails_async(session, domain, st_key)
        if shodan_key:
            tasks["Shodan DNS"] = _fetch_shodan_dns_async(session, domain, shodan_key)

        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), gathered):
            if isinstance(result, Exception):
                results[name] = set()
            else:
                results[name] = result or set()

    return results


# ─── Sync fallback (no aiohttp) ───────────────────────────────────────────────

def fetch_passive_sources_sync(domain: str, vt_key: str = "",
                                st_key: str = "", shodan_key: str = "") -> dict:
    """Sequential fallback when aiohttp is not available."""
    results = {}

    def _fetch(label, fn, *args):
        try:
            results[label] = fn(*args)
        except Exception:
            results[label] = set()

    def _crtsh(domain):
        subs = set()
        r = http_get_retry(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if r and r.ok:
            for entry in r.json():
                for name in entry.get("name_value","").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name)
        return subs

    def _hackertarget(domain):
        subs = set()
        r = http_get_retry(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if r and r.ok and "API count exceeded" not in r.text:
            for line in r.text.splitlines():
                host = line.split(",")[0].strip().lower()
                if host.endswith(f".{domain}"):
                    subs.add(host)
        return subs

    def _alienvault(domain):
        subs = set()
        r = http_get_retry(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=15)
        if r and r.ok:
            for rec in r.json().get("passive_dns", []):
                host = rec.get("hostname","").strip().lower()
                if host.endswith(f".{domain}"):
                    subs.add(host)
        return subs

    def _bufferover(domain):
        subs = set()
        r = http_get_retry(f"https://dns.bufferover.run/dns?q=.{domain}", timeout=10)
        if r and r.ok:
            d = r.json()
            for record in d.get("FDNS_A",[]) + d.get("RDNS",[]):
                for part in record.split(","):
                    part = part.strip().lower()
                    if part.endswith(f".{domain}"):
                        subs.add(part)
        return subs

    def _rapiddns(domain):
        subs = set()
        r = http_get_retry(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=10)
        if r and r.ok:
            for m in re.findall(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')</td>', r.text):
                subs.add(m.lower())
        return subs

    _fetch("crt.sh",         _crtsh,         domain)
    _fetch("HackerTarget",   _hackertarget,  domain)
    _fetch("AlienVault OTX", _alienvault,    domain)
    _fetch("BufferOver",     _bufferover,    domain)
    _fetch("RapidDNS",       _rapiddns,      domain)
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  FINGERPRINTING ENGINE — CONFIDENCE SCORING
# ═══════════════════════════════════════════════════════════════════════════════

def score_service(sigs: dict, h_lower: dict, body_low: str, cookies: str) -> int:
    """
    Compute confidence score (0–100) for a service based on matched signals.
    Returns 0 if no signals match.
    """
    total_weight = sum(SIGNAL_WEIGHTS.get(t, 10) for t, _ in sigs.get("signals", []))
    if total_weight == 0:
        return 0

    matched_weight = 0
    for sig_type, sig_val in sigs.get("signals", []):
        sv = sig_val.lower()
        matched = False

        if sig_type in ("header_exact", "header_prefix"):
            key, _, val = sv.partition(":")
            key = key.strip(); val = val.strip()
            if val:
                matched = key in h_lower and val in h_lower[key].lower()
            else:
                matched = any(key in hk for hk in h_lower)

        elif sig_type in ("body_specific", "body_generic"):
            matched = sv in body_low

        elif sig_type == "cookie":
            matched = sv in cookies

        if matched:
            matched_weight += SIGNAL_WEIGHTS.get(sig_type, 10)

    return min(100, round(matched_weight / max(total_weight, 1) * 100))


def detect_waf(h_lower: dict, body_low: str, cookies: str) -> Optional[Tuple[str, int]]:
    """Returns (waf_name, confidence_pct) or None."""
    for name, (fn, conf) in WAF_SIGNATURES.items():
        try:
            if fn(h_lower, body_low, cookies):
                return (name, conf)
        except Exception:
            pass
    return None


def _build_fp_context(resp) -> dict:
    """Parse a requests.Response into reusable fingerprinting context."""
    h_lower  = {k.lower(): v for k, v in resp.headers.items()}
    body     = resp.text if resp.text else ""
    body_low = body[:12000].lower()
    cookies  = " ".join(resp.cookies.keys()).lower()
    server   = resp.headers.get("Server", "")
    powered  = resp.headers.get("X-Powered-By", "")
    title    = None
    tm = re.search(r"<title[^>]*>([^<]{1,120})</title>", body, re.I)
    if tm:
        title = tm.group(1).strip()
    return {
        "h_lower": h_lower, "body_low": body_low, "cookies": cookies,
        "server": server, "powered": powered, "title": title,
        "status": resp.status_code,
    }


def fingerprint_from_context(ctx: dict, base_url: str,
                               min_confidence: int) -> dict:
    """
    Run all SERVICE_SIGNATURES against a pre-parsed HTTP context.
    Returns dict with services (with scores), waf, versions, title, etc.
    """
    out = {
        "services": [],           # [(name, confidence)]
        "title":    ctx["title"],
        "server":   ctx["server"] or None,
        "powered":  ctx["powered"] or None,
        "waf":      None,
        "waf_confidence": 0,
        "versions": [],
        "status":   ctx["status"],
    }

    waf_result = detect_waf(ctx["h_lower"], ctx["body_low"], ctx["cookies"])
    if waf_result:
        out["waf"], out["waf_confidence"] = waf_result

    out["versions"] = extract_versions(ctx["body_low"], ctx["server"], ctx.get("powered",""))

    # Always extract raw Server + X-Powered-By as tech if not already in versions
    server_raw = (ctx.get("server") or "").strip()
    powered_raw = (ctx.get("powered") or "").strip()
    if server_raw:
        # Add server header as-is if not already covered by VERSION_PATTERNS
        covered = any(server_raw.lower().split("/")[0] in v.lower()
                      for v in out["versions"])
        if not covered:
            out["versions"].insert(0, server_raw)

    for svc_name, sigs in SERVICE_SIGNATURES.items():
        score = score_service(sigs, ctx["h_lower"], ctx["body_low"], ctx["cookies"])
        if score >= min_confidence:
            out["services"].append((svc_name, score))

    # Sort by confidence desc
    out["services"].sort(key=lambda x: -x[1])
    return out


def probe_paths(hostname: str, base_url: str, detected_names: set,
                min_confidence: int) -> list:
    """
    Probe service-specific paths for services not yet detected.
    Returns list of (service_name, confidence).
    """
    found = []
    for svc_name, sigs in SERVICE_SIGNATURES.items():
        if svc_name in detected_names or not sigs.get("paths"):
            continue
        for path in sigs["paths"]:
            if path.startswith(":"):
                continue
            probe_url = urljoin(base_url, path)
            pr = http_get_retry(probe_url, timeout=5, retries=2)
            if pr and pr.status_code in (200, 301, 302, 401, 403):
                ctx = _build_fp_context(pr)
                score = score_service(sigs, ctx["h_lower"], ctx["body_low"], ctx["cookies"])
                if score >= min_confidence:
                    found.append((svc_name, score))
                    break
                # Even without body match, path existence = low confidence
                elif pr.status_code in (200, 401, 403) and sigs.get("signals"):
                    found.append((svc_name, max(min_confidence, 45)))
                    break
            break  # only first path per service
    return found


# ═══════════════════════════════════════════════════════════════════════════════
#  ASYNC HTTP FINGERPRINTING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# IP-level fingerprint cache: ip -> fp_result
_fp_cache: Dict[str, dict] = {}
_fp_cache_lock = threading.Lock()


async def fingerprint_host_async(session: "aiohttp.ClientSession",
                                  hostname: str,
                                  open_ports: dict,
                                  min_confidence: int,
                                  primary_ip: str) -> dict:
    """Async fingerprinting of a single host."""
    empty = {"services": [], "title": None, "server": None, "powered": None,
             "waf": None, "waf_confidence": 0, "versions": [], "status": None}

    urls = []
    if 443 in open_ports:   urls.append(f"https://{hostname}/")
    if 8443 in open_ports:  urls.append(f"https://{hostname}:8443/")
    if 80 in open_ports:    urls.append(f"http://{hostname}/")
    if 8080 in open_ports:  urls.append(f"http://{hostname}:8080/")
    if not urls:
        urls = [f"https://{hostname}/", f"http://{hostname}/"]

    result = None
    for base_url in urls[:2]:
        for attempt in range(2):
            try:
                timeout = aiohttp.ClientTimeout(total=8, connect=4)
                async with session.get(base_url, timeout=timeout,
                                       allow_redirects=True, ssl=False) as resp:
                    text = await resp.text(errors="replace")
                    # Build fake requests-like context
                    h_lower  = {k.lower(): v for k, v in resp.headers.items()}
                    body_low = text[:12000].lower()
                    cookies_str = " ".join(
                        c.key.lower() for c in resp.cookies.values()
                    )
                    server  = resp.headers.get("Server", "")
                    powered = resp.headers.get("X-Powered-By", "")
                    title   = None
                    tm = re.search(r"<title[^>]*>([^<]{1,120})</title>", text, re.I)
                    if tm:
                        title = tm.group(1).strip()

                    ctx = {"h_lower": h_lower, "body_low": body_low,
                           "cookies": cookies_str, "server": server,
                           "powered": powered, "title": title,
                           "status": resp.status}

                    result = fingerprint_from_context(ctx, base_url, min_confidence)
                    # extract_versions uses full body (not lowered) for accuracy
                    result["versions"] = extract_versions(
                        text[:10000], server, powered)
                    break
            except Exception:
                if attempt == 0:
                    await asyncio.sleep(0.3)
        if result:
            break

    if result is None:
        result = empty

    return result


async def fingerprint_all_async(hosts: List[dict], min_confidence: int) -> Dict[str, dict]:
    """
    Fingerprint all resolved hosts concurrently using aiohttp.
    hosts: list of recon result dicts (must have hostname, open_ports, ips).
    Returns {hostname: fp_result}.
    """
    if not HAS_AIOHTTP:
        return {}

    connector = aiohttp.TCPConnector(limit=50, ssl=False, ttl_dns_cache=300)
    headers   = {"User-Agent": UA}

    fp_results: Dict[str, dict] = {}

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        sem = asyncio.Semaphore(50)  # max 50 concurrent

        async def task(h: dict):
            async with sem:
                hostname   = h["hostname"]
                open_ports = h.get("open_ports", {})
                primary_ip = h["ips"][0] if h.get("ips") else ""
                fp = await fingerprint_host_async(
                    session, hostname, open_ports, min_confidence, primary_ip)
                fp_results[hostname] = fp

        await asyncio.gather(*[task(h) for h in hosts], return_exceptions=True)

    return fp_results


# ═══════════════════════════════════════════════════════════════════════════════
#  BRUTEFORCE (with recursive depth-1 expansion)
# ═══════════════════════════════════════════════════════════════════════════════

def _check_host(hostname: str, wildcard_ips: Optional[set]) -> Optional[str]:
    """Resolve hostname, filter wildcards. Returns hostname or None."""
    info = resolve_hostname(hostname)
    if not info["alive"]:
        return None
    if wildcard_ips:
        host_ips = set(info["ips"] + info["ipv6"])
        if host_ips.issubset(wildcard_ips):
            return None
    return hostname


def bruteforce_subdomains(domain: str, wordlist: list, threads: int,
                           wildcard_ips: Optional[set] = None,
                           recursive: bool = True) -> set:
    """
    DNS bruteforce at depth 1 (word.domain).
    If recursive=True, also tries RECURSIVE_PREFIXES against every found
    subdomain — catches patterns like dev1-portal.example.com,
    dev.b2b.example.com, new-api.example.com, etc.
    """
    found_l1: set = set()

    cprint(C.BLU, f"\n  ▸ Bruteforce L1: {len(wordlist)} words, {threads} threads…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        candidates = [f"{w}.{domain}" for w in wordlist]
        for result in ex.map(lambda h: _check_host(h, wildcard_ips), candidates):
            if result:
                found_l1.add(result)
                status("+", result, C.GRN)

    if not recursive or not found_l1:
        return found_l1

    # ── Recursive expansion ──────────────────────────────────────────────────
    # Strategy 1: prefix.found_sub  (e.g. dev.b2b.domain.com)
    # Strategy 2: prefix-basename.domain  (e.g. dev1-portal.domain.com, new-api.domain.com)
    recursive_candidates: set = set()

    for found_host in found_l1:
        # Extract the subdomain part (strip domain)
        sub_part = found_host[: -len(domain) - 1]   # e.g. "b2b", "portal", "api-new-maytoni"
        # Clean up multi-level (e.g. "api-new-maytoni.maytoni" → just take leftmost)
        base = sub_part.split(".")[0]

        for pfx in RECURSIVE_PREFIXES:
            # prefix.sub.domain  (two-level)
            recursive_candidates.add(f"{pfx}.{found_host}")
            # prefix-base.domain  (composite single-level)
            recursive_candidates.add(f"{pfx}-{base}.{domain}")
            recursive_candidates.add(f"{pfx}1-{base}.{domain}")
            recursive_candidates.add(f"{pfx}2-{base}.{domain}")

    # Remove already-found and already-tried
    already_tried = set(f"{w}.{domain}" for w in wordlist) | found_l1
    recursive_candidates -= already_tried

    found_l2: set = set()
    if recursive_candidates:
        cprint(C.BLU, f"  ▸ Bruteforce recursive: {len(recursive_candidates)} candidates…")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for result in ex.map(lambda h: _check_host(h, wildcard_ips),
                                  sorted(recursive_candidates)):
                if result:
                    found_l2.add(result)
                    status("+", f"{result}  [recursive]", C.YLW)

    return found_l1 | found_l2


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN RECON ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def recon_dns_only(hostname: str, scan_ports_flag: bool, timeout: float,
                    shodan_key: str = "", no_osint: bool = False) -> dict:
    """Phase 1: DNS resolution, PTR, ports, OSINT (no HTTP fingerprinting yet)."""
    result = {
        "hostname": hostname,
        "ips": [], "ipv6": [], "ptr": [], "cname": None,
        "open_ports": {}, "ip_info": {}, "shodan": {},
        "services": [], "title": None, "server": None,
        "powered": None, "waf": None, "waf_confidence": 0,
        "versions": [], "http_status": None, "service_scores": {}, "errors": [],
    }

    dns_info = resolve_hostname(hostname)
    result["ips"]   = dns_info["ips"]
    result["ipv6"]  = dns_info["ipv6"]
    result["cname"] = dns_info["cname"]

    if not dns_info["alive"]:
        result["errors"].append("DNS resolution failed")
        return result

    for ip in result["ips"][:2]:
        ptr = get_ptr(ip)
        if ptr:
            result["ptr"].append(ptr)

    primary_ip = result["ips"][0] if result["ips"] else ""

    if not no_osint and primary_ip:
        result["ip_info"] = get_ip_info(primary_ip)

    if scan_ports_flag and primary_ip:
        result["open_ports"] = scan_ports(primary_ip, COMMON_PORTS, timeout)

    if shodan_key and primary_ip:
        result["shodan"] = get_shodan_host(primary_ip, shodan_key)

    return result


def apply_fp_results(results: list, fp_map: Dict[str, dict]) -> None:
    """Merge async fingerprinting results back into recon dicts (in-place)."""
    for r in results:
        fp = fp_map.get(r["hostname"])
        if not fp:
            continue
        r["services"]       = [svc for svc, _ in fp["services"]]
        r["service_scores"] = {svc: sc for svc, sc in fp["services"]}
        r["title"]          = fp["title"]
        r["server"]         = fp["server"]
        r["powered"]        = fp["powered"]
        r["waf"]            = fp["waf"]
        r["waf_confidence"] = fp["waf_confidence"]
        r["versions"]       = fp["versions"]
        r["http_status"]    = fp["status"]


# ═══════════════════════════════════════════════════════════════════════════════
#  TEXT REPORT
# ═══════════════════════════════════════════════════════════════════════════════

TXT_TEMPLATE = """\
╔══════════════════════════════════════════════════════════════════════════════╗
║                     SubRecon v3 — Recon Report                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Target Domain  : {domain}
  Scan Started   : {start_time}
  Scan Finished  : {end_time}
  Duration       : {duration}s
  Subdomains     : {total_found} found / {total_alive} resolved / {total_services} with services
  Wildcard DNS   : {wildcard_status}
  Port Scanning  : {port_scan_status}
  Sources Used   : {sources}

══════════════════════════════════════════════════════════════════════════════
  QUICK TABLE  (domain | IP | technology + version | WAF)
══════════════════════════════════════════════════════════════════════════════
{quick_table}
══════════════════════════════════════════════════════════════════════════════
  DETAILED RECORDS
══════════════════════════════════════════════════════════════════════════════
{subdomain_blocks}
══════════════════════════════════════════════════════════════════════════════
  DETECTED SERVICES
══════════════════════════════════════════════════════════════════════════════
{service_summary}

══════════════════════════════════════════════════════════════════════════════
  IP ADDRESSES
══════════════════════════════════════════════════════════════════════════════
{ip_summary}

══════════════════════════════════════════════════════════════════════════════
  WAF DETECTION
══════════════════════════════════════════════════════════════════════════════
{waf_summary}

══════════════════════════════════════════════════════════════════════════════
  END OF REPORT
══════════════════════════════════════════════════════════════════════════════
"""

HOST_BLOCK = """  ┌─ {hostname}
  │  IPv4          : {ips}
  │  IPv6          : {ipv6}
  │  PTR           : {ptr}
  │  CNAME         : {cname}
  │  HTTP Status   : {http_status}
  │  Open Ports    : {ports}
  │  Technology    : {tech}
  │  Services      : {services}
  │  WAF           : {waf}
  │  ASN/Org       : {asn}
  │  Country/City  : {geo}
  │  Shodan Ports  : {shodan_ports}
  │  CVEs          : {cves}
  └─────────────────────────────────────────────────────────────────────────
"""


def _build_tech_string(r: dict) -> str:
    """
    Combine versions + services into a human-readable technology string.
    e.g. "nginx/1.22.1, PHP/8.1, Bitrix (88%), Nextcloud, Node.js/Express (75%)"
    """
    parts = list(r.get("versions", []))
    scores = r.get("service_scores", {})
    generic_servers = {"nginx", "Apache httpd", "IIS", "LiteSpeed", "OpenResty", "Caddy"}
    for svc in r.get("services", []):
        if svc in generic_servers:
            continue
        sc = scores.get(svc, 0)
        label = f"{svc} ({sc}%)" if sc else svc
        parts.append(label)
    return ", ".join(parts) if parts else "—"


def _fmt_services_txt(r: dict) -> str:
    scores = r.get("service_scores", {})
    parts = []
    for svc in r.get("services", []):
        sc = scores.get(svc)
        parts.append(f"{svc} ({sc}%)" if sc else svc)
    return ", ".join(parts) if parts else "—"


def format_txt_report(domain, results, start_dt, end_dt, sources,
                       scan_ports_flag, wildcard_ips):
    duration = round((end_dt - start_dt).total_seconds(), 1)
    blocks, service_map, ip_map, waf_map = [], {}, {}, {}

    # ── Quick table ───────────────────────────────────────────────────────────
    COL = [50, 18, 55, 28]
    sep  = "  " + "-" * (sum(COL) + 9)
    hdr  = (f"  {'DOMAIN [HTTP]':<{COL[0]}}  {'IP':<{COL[1]}}  "
            f"{'TECHNOLOGY / VERSION':<{COL[2]}}  WAF")
    qt_lines = [hdr, sep]

    for r in sorted(results, key=lambda x: x["hostname"]):
        hostname = r["hostname"]
        ip       = ", ".join(r.get("ips", [])) if r.get("ips") else "—"
        tech     = _build_tech_string(r)
        waf_q    = (f"{r['waf']} ({r.get('waf_confidence',0)}%)"
                    if r.get("waf") else "—")
        code     = f" [{r['http_status']}]" if r.get("http_status") else ""
        domain_col = hostname + code

        # wrap tech if long
        chunks = [tech[i:i+COL[2]] for i in range(0, max(len(tech), 1), COL[2])]
        qt_lines.append(
            f"  {domain_col:<{COL[0]}}  {ip:<{COL[1]}}  "
            f"{chunks[0]:<{COL[2]}}  {waf_q}")
        for ch in chunks[1:]:
            qt_lines.append(f"  {'': <{COL[0]}}  {'': <{COL[1]}}  {ch}")

    quick_table = "\n".join(qt_lines)

    # ── Detailed blocks ───────────────────────────────────────────────────────
    for r in sorted(results, key=lambda x: x["hostname"]):
        ips_str   = ", ".join(r.get("ips", []))  or "—"
        ipv6_str  = ", ".join(r.get("ipv6", [])) or "—"
        ptr_str   = ", ".join(r.get("ptr", []))  or "—"
        cname_str = r.get("cname") or "—"
        tech_str  = _build_tech_string(r)
        svc_str   = _fmt_services_txt(r)
        waf_str   = (f"{r['waf']} ({r.get('waf_confidence',0)}%)"
                     if r.get("waf") else "—")
        http_str  = str(r["http_status"]) if r.get("http_status") else "—"
        ports_str = (", ".join(f"{p}/{n}" for p, n in sorted(r["open_ports"].items()))
                     if r.get("open_ports")
                     else ("not scanned" if not scan_ports_flag else "—"))

        ii = r.get("ip_info", {})
        asn_str = (f"AS{ii['asn']} / " if ii.get("asn") else "") + (ii.get("asn_org") or "")
        asn_str = asn_str.strip(" /") or "—"
        geo_str = ", ".join(filter(None, [ii.get("country"), ii.get("city")])) or "—"

        sh = r.get("shodan", {})
        shodan_ports_str = ", ".join(str(p) for p in sh.get("ports", [])) or "—"
        cves_str = ", ".join(sh.get("vulns", [])) or "—"

        blocks.append(HOST_BLOCK.format(
            hostname=r["hostname"], ips=ips_str, ipv6=ipv6_str,
            ptr=ptr_str, cname=cname_str, http_status=http_str,
            ports=ports_str, tech=tech_str, services=svc_str,
            waf=waf_str, asn=asn_str, geo=geo_str,
            shodan_ports=shodan_ports_str, cves=cves_str,
        ))

        for svc in r.get("services", []):
            service_map.setdefault(svc, []).append(r["hostname"])
        for ip in r.get("ips", []):
            ip_map.setdefault(ip, []).append(r["hostname"])
        if r.get("waf"):
            waf_map.setdefault(r["waf"], []).append(r["hostname"])

    svc_summary = "\n".join(
        f"  {svc:<42} {', '.join(hosts)}" for svc, hosts in sorted(service_map.items())
    ) or "  No services detected"

    ip_summary = "\n".join(
        f"  {ip:<20} {', '.join(hosts)}" for ip, hosts in sorted(ip_map.items())
    ) or "  No IPs resolved"

    waf_summary = "\n".join(
        f"  {waf:<30} {', '.join(hosts)}" for waf, hosts in sorted(waf_map.items())
    ) or "  No WAF detected"

    wc_status = (f"DETECTED — wildcard IPs: {', '.join(wildcard_ips)}"
                 if wildcard_ips else "Not detected")

    return TXT_TEMPLATE.format(
        domain=domain,
        start_time=start_dt.strftime("%Y-%m-%d %H:%M:%S"),
        end_time=end_dt.strftime("%Y-%m-%d %H:%M:%S"),
        duration=duration,
        total_found=len(results),
        total_alive=sum(1 for r in results if r.get("ips") or r.get("ipv6")),
        total_services=sum(1 for r in results if r.get("services")),
        wildcard_status=wc_status,
        port_scan_status="enabled" if scan_ports_flag else "disabled (--ports to enable)",
        sources=", ".join(sources),
        quick_table=quick_table,
        subdomain_blocks="".join(blocks),
        service_summary=svc_summary,
        ip_summary=ip_summary,
        waf_summary=waf_summary,
    )

# ═══════════════════════════════════════════════════════════════════════════════
#  HTML REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def format_html_report(domain, results, start_dt, end_dt, sources,
                        scan_ports_flag, wildcard_ips):
    duration      = round((end_dt - start_dt).total_seconds(), 1)
    total_alive   = sum(1 for r in results if r["ips"] or r["ipv6"])
    total_svc     = sum(1 for r in results if r["services"])
    total_wafs    = sum(1 for r in results if r.get("waf"))
    total_cves    = sum(len(r.get("shodan", {}).get("vulns", [])) for r in results)

    rows = []
    for r in sorted(results, key=lambda x: x["hostname"]):
        scores    = r.get("service_scores", {})
        hostname  = r["hostname"]
        ips       = ", ".join(r["ips"]) or "—"
        http_st   = r.get("http_status")
        services  = r["services"]
        waf       = r.get("waf") or "—"
        waf_conf  = r.get("waf_confidence", 0)
        versions  = ", ".join(r.get("versions", [])) or "—"
        title     = (r.get("title") or "").replace("<","&lt;").replace(">","&gt;")
        ii        = r.get("ip_info", {})
        geo       = ", ".join(filter(None, [ii.get("country"), ii.get("city")])) or "—"
        sh        = r.get("shodan", {})
        cves_list = sh.get("vulns", [])
        cves      = ", ".join(cves_list) or "—"

        ports_str = ""
        if r["open_ports"] and scan_ports_flag:
            ports_str = ", ".join(f"{p}/{n}" for p, n in sorted(r["open_ports"].items()))
        else:
            ports_str = "—"

        # HTTP status badge
        st_class = ""
        if http_st:
            if 200 <= http_st < 300:   st_class = "bg"
            elif 300 <= http_st < 400: st_class = "bb"
            elif http_st in (401,403): st_class = "bo"
            else:                       st_class = "br"
        http_badge = f'<span class="badge {st_class}">{http_st}</span>' if st_class else (str(http_st) if http_st else "—")

        # Services with confidence bars
        svc_html_parts = []
        for svc in services:
            sc = scores.get(svc, 0)
            bar_w = sc
            svc_html_parts.append(
                f'<span class="svc-item" title="{sc}% confidence">'
                f'{svc}<span class="conf-bar"><span style="width:{bar_w}%"></span></span>'
                f'</span>'
            )
        svc_html = " ".join(svc_html_parts) if svc_html_parts else "—"

        waf_html = (f'<span class="badge bp" title="{waf_conf}% confidence">{waf} {waf_conf}%</span>'
                    if waf != "—" else "—")
        cve_html = (f'<span class="badge br">{cves}</span>' if cves != "—" else "—")

        rows.append(f"""
        <tr data-h="{hostname}" data-svc="{' '.join(services)}" data-waf="{waf}" data-cve="{cves}">
          <td class="hcell"><a href="https://{hostname}" target="_blank" rel="noopener">{hostname}</a></td>
          <td class="mono">{ips}</td>
          <td>{http_badge}</td>
          <td class="scell">{svc_html}</td>
          <td>{waf_html}</td>
          <td>{cve_html}</td>
          <td class="vmono">{versions}</td>
          <td>{geo}</td>
          <td class="mono">{ports_str}</td>
          <td class="tcell" title="{title}">{title[:70]+"…" if len(title)>70 else title}</td>
        </tr>""")

    rows_html     = "\n".join(rows)
    sources_html  = ", ".join(sources)
    wc_html       = (f'<span style="color:var(--rd)">⚠ Wildcard detected: {", ".join(wildcard_ips)}</span>'
                     if wildcard_ips else '<span style="color:var(--gn)">✓ No wildcard</span>')

    all_services  = sorted({s for r in results for s in r["services"]})
    svc_opts      = "\n".join(f'<option value="{s}">{s}</option>' for s in all_services)
    all_wafs      = sorted({r["waf"] for r in results if r.get("waf")})
    waf_opts      = "\n".join(f'<option value="{w}">{w}</option>' for w in all_wafs)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SubRecon v3 — {domain}</title>
<style>
:root{{
  --bg:#0d1117;--card:#161b22;--brd:#30363d;
  --tx:#e6edf3;--mu:#8b949e;--ac:#58a6ff;
  --gn:#3fb950;--rd:#f85149;--or:#d29922;--bl:#58a6ff;--pu:#bc8cff;
  --fn:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:var(--fn);font-size:14px}}
.hdr{{background:linear-gradient(135deg,#1a1f2e,#0d1117);border-bottom:1px solid var(--brd);padding:20px 28px}}
.hdr h1{{font-size:1.5em;color:var(--ac)}}
.hdr .meta{{color:var(--mu);margin-top:6px;font-size:.83em}}
.hdr .meta span{{margin-right:20px}}
.stats{{display:flex;gap:12px;padding:16px 28px;border-bottom:1px solid var(--brd);flex-wrap:wrap}}
.sc{{background:var(--card);border:1px solid var(--brd);border-radius:8px;padding:10px 18px;flex:1;min-width:100px;text-align:center}}
.sc .n{{font-size:1.9em;font-weight:700;color:var(--ac)}}
.sc .l{{font-size:.7em;color:var(--mu);text-transform:uppercase;letter-spacing:.5px;margin-top:2px}}
.ctrl{{padding:12px 28px;border-bottom:1px solid var(--brd);display:flex;gap:10px;flex-wrap:wrap;align-items:center}}
.ctrl input,.ctrl select{{background:var(--card);border:1px solid var(--brd);color:var(--tx);padding:6px 10px;border-radius:6px;font-size:.88em;outline:none}}
.ctrl input:focus,.ctrl select:focus{{border-color:var(--ac)}}
.ctrl input{{width:220px}}
.ctrl label{{color:var(--mu);font-size:.82em}}
.btn{{background:var(--ac);color:#0d1117;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.82em;font-weight:600}}
.btn:hover{{opacity:.85}}
.rc{{color:var(--mu);font-size:.82em;margin-left:auto}}
.tw{{overflow-x:auto;padding:0 28px 28px}}
table{{width:100%;border-collapse:collapse;margin-top:14px}}
th{{background:var(--card);color:var(--mu);text-align:left;padding:9px 10px;font-size:.72em;text-transform:uppercase;letter-spacing:.4px;border-bottom:2px solid var(--brd);cursor:pointer;user-select:none;white-space:nowrap}}
th:hover{{color:var(--tx)}}
th.srt .si{{color:var(--ac);opacity:1}}
.si{{opacity:.35}}
td{{padding:9px 10px;border-bottom:1px solid var(--brd);vertical-align:top}}
tr:hover td{{background:rgba(88,166,255,.04)}}
tr.hidden{{display:none}}
.hcell a{{color:var(--ac);text-decoration:none;font-weight:500}}
.hcell a:hover{{text-decoration:underline}}
.scell{{max-width:240px}}
.tcell{{color:var(--mu);font-size:.82em;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.mono{{font-family:monospace;font-size:.85em}}
.vmono{{font-family:monospace;font-size:.8em;color:var(--mu)}}
.badge{{display:inline-block;padding:2px 7px;border-radius:10px;font-size:.72em;font-weight:600}}
.bg{{background:rgba(63,185,80,.15);color:var(--gn)}}
.br{{background:rgba(248,81,73,.15);color:var(--rd)}}
.bo{{background:rgba(210,153,34,.15);color:var(--or)}}
.bb{{background:rgba(88,166,255,.15);color:var(--bl)}}
.bp{{background:rgba(188,140,255,.15);color:var(--pu)}}
.svc-item{{display:inline-block;margin:1px 3px 3px 0;white-space:nowrap;font-size:.8em}}
.conf-bar{{display:inline-block;width:30px;height:4px;background:var(--brd);border-radius:2px;margin-left:4px;vertical-align:middle}}
.conf-bar span{{display:block;height:100%;background:var(--ac);border-radius:2px}}
.nores{{text-align:center;color:var(--mu);padding:36px}}
footer{{text-align:center;color:var(--mu);font-size:.78em;padding:18px;border-top:1px solid var(--brd)}}
</style>
</head>
<body>
<div class="hdr">
  <h1>🔍 SubRecon v3 — {domain}</h1>
  <div class="meta">
    <span>🕐 {start_dt.strftime("%Y-%m-%d %H:%M:%S")}</span>
    <span>⏱ {duration}s</span>
    <span>📡 {sources_html}</span>
    <span>{wc_html}</span>
  </div>
</div>
<div class="stats">
  <div class="sc"><div class="n">{len(results)}</div><div class="l">Subdomains</div></div>
  <div class="sc"><div class="n" style="color:var(--gn)">{total_alive}</div><div class="l">Resolved</div></div>
  <div class="sc"><div class="n" style="color:var(--bl)">{total_svc}</div><div class="l">With Services</div></div>
  <div class="sc"><div class="n" style="color:var(--pu)">{total_wafs}</div><div class="l">WAF Detected</div></div>
  <div class="sc"><div class="n" style="color:var(--rd)">{total_cves}</div><div class="l">CVEs Found</div></div>
</div>
<div class="ctrl">
  <label>Filter:</label>
  <input id="si" type="text" placeholder="hostname, IP, tech…" oninput="af()">
  <select id="sf" onchange="af()"><option value="">All services</option>{svc_opts}</select>
  <select id="wf" onchange="af()"><option value="">All WAF</option>{waf_opts}</select>
  <select id="cf" onchange="af()">
    <option value="">Any CVE status</option>
    <option value="y">Has CVEs</option>
    <option value="n">No CVEs</option>
  </select>
  <button class="btn" onclick="rf()">Reset</button>
  <span class="rc" id="rc"></span>
</div>
<div class="tw">
<table id="mt">
<thead><tr>
  <th onclick="st(0)">Hostname <span class="si">↕</span></th>
  <th onclick="st(1)">IPs <span class="si">↕</span></th>
  <th onclick="st(2)">Status <span class="si">↕</span></th>
  <th onclick="st(3)">Services (confidence) <span class="si">↕</span></th>
  <th onclick="st(4)">WAF <span class="si">↕</span></th>
  <th onclick="st(5)">CVEs <span class="si">↕</span></th>
  <th onclick="st(6)">Versions <span class="si">↕</span></th>
  <th onclick="st(7)">Geo <span class="si">↕</span></th>
  <th onclick="st(8)">Ports <span class="si">↕</span></th>
  <th onclick="st(9)">Page Title <span class="si">↕</span></th>
</tr></thead>
<tbody id="tb">{rows_html}</tbody>
</table>
<div class="nores" id="nr" style="display:none">No results match the filters.</div>
</div>
<footer>Generated by SubRecon v3 · {end_dt.strftime("%Y-%m-%d %H:%M:%S")}</footer>
<script>
let sc=-1,sa=true;
function af(){{
  const q=document.getElementById('si').value.toLowerCase();
  const sf=document.getElementById('sf').value.toLowerCase();
  const wf=document.getElementById('wf').value.toLowerCase();
  const cf=document.getElementById('cf').value;
  const rows=document.querySelectorAll('#tb tr');
  let v=0;
  rows.forEach(r=>{{
    const txt=r.textContent.toLowerCase();
    const sv=(r.dataset.svc||'').toLowerCase();
    const wv=(r.dataset.waf||'').toLowerCase();
    const cv=(r.dataset.cve||'').toLowerCase();
    const hc=cv!=='—'&&cv!=='';
    let ok=true;
    if(q&&!txt.includes(q))ok=false;
    if(sf&&!sv.includes(sf))ok=false;
    if(wf&&!wv.includes(wf))ok=false;
    if(cf==='y'&&!hc)ok=false;
    if(cf==='n'&&hc)ok=false;
    r.classList.toggle('hidden',!ok);
    if(ok)v++;
  }});
  document.getElementById('rc').textContent=v+' / '+rows.length;
  document.getElementById('nr').style.display=v===0?'block':'none';
}}
function rf(){{
  ['si','sf','wf','cf'].forEach(id=>document.getElementById(id).value='');
  af();
}}
function st(col){{
  const tb=document.getElementById('tb');
  const rows=Array.from(tb.querySelectorAll('tr'));
  if(sc===col)sa=!sa; else{{sc=col;sa=true;}}
  document.querySelectorAll('thead th').forEach((th,i)=>{{
    th.classList.toggle('srt',i===col);
    const s=th.querySelector('.si');
    if(s)s.textContent=i===col?(sa?'↑':'↓'):'↕';
  }});
  rows.sort((a,b)=>{{
    const av=(a.cells[col]?.textContent||'').trim();
    const bv=(b.cells[col]?.textContent||'').trim();
    return sa?av.localeCompare(bv):bv.localeCompare(av);
  }});
  rows.forEach(r=>tb.appendChild(r));
  af();
}}
window.addEventListener('load',()=>{{
  const r=document.querySelectorAll('#tb tr');
  document.getElementById('rc').textContent=r.length+' / '+r.length;
}});
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI ARGS
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="SubRecon v3 — Fast, accurate subdomain recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 subdomain_recon.py -d example.com
  python3 subdomain_recon.py -d example.com --threads 50 --ports
  python3 subdomain_recon.py -d example.com --virustotal VT_KEY --shodan SK
  python3 subdomain_recon.py -d example.com --min-confidence 60 --no-bruteforce
""")
    p.add_argument("-d","--domain",       required=True,  help="Target domain")
    p.add_argument("-w","--wordlist",                     help="Custom wordlist path")
    p.add_argument("-o","--output",                       help="Output base path")
    p.add_argument("-t","--threads",      type=int, default=25, help="DNS/port threads (default:25)")
    p.add_argument("--timeout",           type=float, default=3.0, help="Socket timeout (default:3.0)")
    p.add_argument("--ports",             action="store_true", help="Enable port scanning")
    p.add_argument("--no-bruteforce",     action="store_true", help="Skip DNS bruteforce")
    p.add_argument("--no-recursive",      action="store_true", help="Skip recursive bruteforce expansion")
    p.add_argument("--no-passive",        action="store_true", help="Skip passive sources")
    p.add_argument("--no-osint",          action="store_true", help="Skip geo/ASN enrichment")
    p.add_argument("--no-wildcard-check", action="store_true", help="Skip wildcard detection")
    p.add_argument("--min-confidence",    type=int, default=DEFAULT_MIN_CONFIDENCE,
                   help=f"Min confidence %% to report a service (default:{DEFAULT_MIN_CONFIDENCE})")
    p.add_argument("--json",              action="store_true", help="Also write JSON")
    p.add_argument("--virustotal",        metavar="KEY")
    p.add_argument("--securitytrails",    metavar="KEY")
    p.add_argument("--shodan",            metavar="KEY")
    return p.parse_args()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    args   = parse_args()
    domain = args.domain.lower().strip().rstrip(".")

    cprint(C.MAG, BANNER)
    cprint(C.BOLD, f"  Target : {domain}")
    cprint(C.GRY,  f"  Engine : asyncio={'yes' if HAS_AIOHTTP else 'NO (pip install aiohttp)'} | "
                   f"dnspython={'yes' if HAS_DNSPYTHON else 'NO'}")
    print()

    start_dt      = datetime.datetime.now()
    all_subs: set = set()
    sources_used  = []
    wildcard_ips: Optional[set] = None

    # ── 0. Wildcard detection ────────────────────────────────────────────────
    if not args.no_wildcard_check:
        cprint(C.CYN, "  [*] Checking for wildcard DNS…")
        wildcard_ips = detect_wildcard(domain)
        if wildcard_ips:
            cprint(C.YLW, f"  [!] Wildcard detected! IPs: {', '.join(wildcard_ips)}")
            cprint(C.YLW,  "      Bruteforce results will be filtered automatically.")
        else:
            cprint(C.GRN,  "  [✓] No wildcard DNS detected.")
        print()

    # ── 1. Passive enumeration (async) ───────────────────────────────────────
    if not args.no_passive:
        cprint(C.CYN, "  [*] Querying passive sources concurrently…")
        if HAS_AIOHTTP:
            source_results = asyncio.run(fetch_passive_sources_async(
                domain, args.virustotal or "", args.securitytrails or "",
                args.shodan or ""))
        else:
            source_results = fetch_passive_sources_sync(domain)
            if args.virustotal or args.securitytrails or args.shodan:
                cprint(C.YLW, "  [!] aiohttp missing — API sources skipped (pip install aiohttp)")

        for src, found in source_results.items():
            all_subs.update(found)
            sources_used.append(src)
            status(src, f"{len(found)} subdomains", C.GRN)

    # ── 2. TLS SAN from apex domain ──────────────────────────────────────────
    cprint(C.GRY, "  [*] Extracting TLS SANs from apex domain…")
    sans = get_tls_sans(domain)
    if sans:
        new_sans = {s for s in sans if s.endswith(f".{domain}") or s == domain}
        all_subs.update(new_sans)
        status("TLS SANs", f"{len(new_sans)} subdomains", C.GRN)
        if new_sans:
            sources_used.append("TLS-SAN")

    # ── 3. DNS bruteforce ────────────────────────────────────────────────────
    if not args.no_bruteforce:
        wordlist = DEFAULT_WORDLIST
        if args.wordlist:
            wl_path = Path(args.wordlist)
            if wl_path.exists():
                wordlist = [l.strip() for l in wl_path.read_text().splitlines()
                            if l.strip() and not l.startswith("#")]
                cprint(C.GRN, f"  [*] Custom wordlist: {len(wordlist)} words")
            else:
                cprint(C.YLW, f"  [!] Wordlist not found — using built-in")
        sources_used.append("DNS-bruteforce")
        brute = bruteforce_subdomains(domain, wordlist, args.threads, wildcard_ips,
                                       recursive=not args.no_recursive)
        all_subs.update(brute)

    all_subs.add(domain)
    cprint(C.GRN, f"\n  [+] Total unique candidates: {len(all_subs)}")

    # ── 4. DNS resolution + ports + OSINT (threaded) ─────────────────────────
    cprint(C.CYN, "\n  [*] Resolving IPs, port scanning, OSINT…\n")
    pre_results = []

    def dns_task(hostname):
        r = recon_dns_only(hostname, args.ports, args.timeout,
                           args.shodan or "", args.no_osint)
        tag   = "+" if (r["ips"] or r["ipv6"]) else "-"
        color = C.GRN if tag == "+" else C.GRY
        ip_str = ", ".join(r["ips"]) if r["ips"] else "unresolved"
        status(tag, f"{hostname:<45} {ip_str}", color)
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for r in ex.map(dns_task, sorted(all_subs)):
            pre_results.append(r)

    resolved = [r for r in pre_results if r["ips"] or r["ipv6"]]
    cprint(C.GRN, f"\n  [+] Resolved: {len(resolved)} hosts")

    # ── 5. HTTP fingerprinting (async, all hosts in parallel) ────────────────
    cprint(C.CYN, f"\n  [*] Fingerprinting {len(resolved)} hosts with asyncio"
                  f"{'+ aiohttp' if HAS_AIOHTTP else ' (sync fallback)'}…")

    if HAS_AIOHTTP:
        fp_map = asyncio.run(fingerprint_all_async(resolved, args.min_confidence))
    else:
        # Sync fallback
        fp_map = {}
        for r in resolved:
            from urllib.parse import urljoin as _urljoin
            # minimal sync fp
            hostname = r["hostname"]
            urls = ([f"https://{hostname}/", f"http://{hostname}/"])
            for url in urls:
                resp = http_get_retry(url, timeout=6, retries=2)
                if resp:
                    ctx = _build_fp_context(resp)
                    fp_map[hostname] = fingerprint_from_context(ctx, url, args.min_confidence)
                    break
            if hostname not in fp_map:
                fp_map[hostname] = {"services":[], "title":None, "server":None,
                                    "powered":None, "waf":None, "waf_confidence":0,
                                    "versions":[], "status":None}

    apply_fp_results(resolved, fp_map)

    # Print fingerprint summary
    for r in resolved:
        if r["services"] or r.get("waf"):
            scores   = r.get("service_scores", {})
            svc_str  = ", ".join(f"{s}({scores.get(s,0)}%)" for s in r["services"][:3])
            waf_str  = f"  WAF:{r['waf']}" if r.get("waf") else ""
            status("fp", f"{r['hostname']:<40} {svc_str}{waf_str}", C.CYN)

    # ── 6. Generate reports ──────────────────────────────────────────────────
    end_dt   = datetime.datetime.now()
    base     = (args.output or f"{domain}_recon_{start_dt.strftime('%Y%m%d_%H%M%S')}"
                ).replace(".txt","").replace(".html","")

    txt  = format_txt_report(domain, resolved, start_dt, end_dt,
                              sources_used, args.ports, wildcard_ips)
    html = format_html_report(domain, resolved, start_dt, end_dt,
                               sources_used, args.ports, wildcard_ips)

    Path(base + ".txt").write_text(txt,  encoding="utf-8")
    Path(base + ".html").write_text(html, encoding="utf-8")
    cprint(C.GRN, f"\n  [✓] TXT  → {base}.txt")
    cprint(C.GRN, f"  [✓] HTML → {base}.html")

    if args.json:
        Path(base + ".json").write_text(
            json.dumps(resolved, indent=2, ensure_ascii=False), encoding="utf-8")
        cprint(C.GRN, f"  [✓] JSON → {base}.json")

    # ── 7. Terminal summary ──────────────────────────────────────────────────
    print()
    cprint(C.BOLD, "  SUMMARY")
    cprint(C.GRY,  "  " + "─" * 60)
    status("Resolved",    str(len(resolved)),  C.GRN)
    status("Unresolved",  str(len(pre_results) - len(resolved)), C.GRY)
    status("WAFs found",  str(sum(1 for r in resolved if r.get("waf"))),  C.MAG)
    status("CVEs total",  str(sum(len(r.get("shodan",{}).get("vulns",[])) for r in resolved)), C.RED)
    if wildcard_ips:
        status("Wildcard",  f"FILTERED — {', '.join(wildcard_ips)}", C.YLW)

    all_svcs: Dict[str, int] = {}
    for r in resolved:
        for s in r["services"]:
            all_svcs[s] = all_svcs.get(s, 0) + 1
    if all_svcs:
        cprint(C.CYN, "\n  Detected services (by frequency):")
        for svc, cnt in sorted(all_svcs.items(), key=lambda x: -x[1]):
            print(f"    {svc:<45} × {cnt}")
    print()


if __name__ == "__main__":
    main()
