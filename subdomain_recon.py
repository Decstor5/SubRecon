#!/usr/bin/env python3
"""
SubRecon v4 — Subdomain Enumeration, Graph Recon & Service Fingerprinting
=========================================================================
Changes vs v3:
  ✦ Graph expansion    — findings feed new findings. Bounded BFS over rounds:
                          resolved hosts -> TLS SANs + JS-extracted hosts ->
                          back into the queue (global `seen` + scope filter).
  ✦ Per-source limits   — AsyncRateLimiter (token bucket) per API/source.
  ✦ Resolver pool       — latency-ranked public resolvers, round-robin, health
                          check, auto-replace. Graceful fallback to system DNS.
  ✦ JS recon            — fetches same-origin JS, extracts endpoints / new hosts
                          / S3 / Firebase / Azure blob / GraphQL / Swagger / WS.
  ✦ DNS enrichment      — MX / NS / TXT / SOA + DNSSEC presence.
  ✦ HTTP depth          — security headers, redirect chain, TLS cert info, CDN.
  ✦ Proxy support       — --proxy http(s)://.. or socks5://..  (SOCKS needs
                          aiohttp_socks). Applies to all async HTTP.
  ✦ New sources         — Chaos, Censys v2, GitHub code search, reverse-IP.
  ✦ Resume              — --resume reloads seen hosts + results from state file.
  ✦ Fixes               — dead BufferOver removed, sync/async source parity,
                          numeric HTML sort, dead code removed, honest IP handling.

Usage:
    python3 subrecon.py -d example.com
    python3 subrecon.py -d example.com --ports --js --depth 2
    python3 subrecon.py -d example.com --chaos KEY --shodan KEY --virustotal KEY
    python3 subrecon.py -d example.com --proxy socks5://127.0.0.1:9050
    python3 subrecon.py -d example.com --scope-file scope.txt --json --resume

Requirements:
    pip install requests dnspython aiohttp
    # optional: aiohttp_socks (SOCKS proxy), ipwhois (RDAP fallback)

NOTE ON AUTHORIZATION:
    Graph expansion (SANs, JS hosts, reverse-IP) will happily wander outside the
    apex domain. By default only the target apex is in scope for requeue. Use
    --scope-file to widen it deliberately. Only test assets you are authorized
    to test. reverse-IP results are REPORT-ONLY and never auto-scanned.
"""

import argparse
import asyncio
import concurrent.futures
import datetime
import itertools
import json
import random
import re
import socket
import ssl
import string
import time
import threading
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Set
from urllib.parse import urljoin, urlparse

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
    from aiohttp_socks import ProxyConnector
    HAS_AIOHTTP_SOCKS = True
except ImportError:
    HAS_AIOHTTP_SOCKS = False

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
        Subdomain Enum · Graph Recon · Fingerprinting   v4.0
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
#  GLOBAL RUNTIME (set in main): resolver pool, rate limiter, proxy config
# ═══════════════════════════════════════════════════════════════════════════════

_POOL: "Optional[ResolverPool]" = None
_RL:   "Optional[AsyncRateLimiter]" = None
# proxy is a tuple: (connector_level_url_or_None, per_request_url_or_None)
_PROXY: Tuple[Optional[str], Optional[str]] = (None, None)

UA = "Mozilla/5.0 (compatible; SubRecon/4.0)"


# ═══════════════════════════════════════════════════════════════════════════════
#  RATE LIMITER  (token bucket, per source)
# ═══════════════════════════════════════════════════════════════════════════════

class AsyncRateLimiter:
    """One instance per run. `await rl.acquire(key)` before each request.
    Unconfigured keys are unlimited. burst = how many may fire back-to-back."""

    def __init__(self):
        self._buckets: dict = {}          # key -> [tokens, last, rate/s, cap]
        self._locks: dict = {}
        self._global_lock = asyncio.Lock()

    def configure(self, key: str, per_minute: float, burst: int = 1):
        rate = per_minute / 60.0
        cap = max(1, int(burst))
        self._buckets[key] = [float(cap), time.monotonic(), rate, float(cap)]

    async def _lock_for(self, key: str) -> asyncio.Lock:
        async with self._global_lock:
            lock = self._locks.get(key)
            if lock is None:
                lock = self._locks[key] = asyncio.Lock()
            return lock

    async def acquire(self, key: str):
        bucket = self._buckets.get(key)
        if bucket is None:
            return
        lock = await self._lock_for(key)
        async with lock:
            while True:
                tokens, last, rate, cap = bucket
                now = time.monotonic()
                tokens = min(cap, tokens + (now - last) * rate)
                if tokens >= 1.0:
                    bucket[0] = tokens - 1.0
                    bucket[1] = now
                    return
                wait = (1.0 - tokens) / rate if rate > 0 else 0.05
                bucket[0], bucket[1] = tokens, now
                await asyncio.sleep(wait)


# ═══════════════════════════════════════════════════════════════════════════════
#  RESOLVER POOL
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_NAMESERVERS = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "64.6.64.6", "64.6.65.6", "77.88.8.8", "77.88.8.1",
    "94.140.14.14", "94.140.15.15", "185.228.168.9",
    "76.76.2.0", "76.76.10.0",
]

class ResolverPool:
    """Latency-ranked public resolvers, round-robin, health check, auto-replace.
    Falls back to system resolver if no candidate is reachable (offline-safe)."""

    def __init__(self, nameservers=None, keep=10, probe_domain="cloudflare.com",
                 timeout=2.0):
        self.candidates = list(nameservers or DEFAULT_NAMESERVERS)
        self.keep = keep
        self.probe_domain = probe_domain
        self.timeout = timeout
        self.healthy: list = []
        self._cycle = None
        self._lock = threading.Lock()

    def _make(self, ns: Optional[str]):
        if not HAS_DNSPYTHON:
            return None
        r = dns.resolver.Resolver(configure=(ns is None))
        if ns:
            r.nameservers = [ns]
        r.timeout = self.timeout
        r.lifetime = self.timeout
        return r

    def _latency(self, ns):
        r = self._make(ns)
        if r is None:
            return None
        try:
            t = time.perf_counter()
            r.resolve(self.probe_domain, "A")
            return time.perf_counter() - t
        except Exception:
            return None

    def benchmark(self) -> list:
        if not HAS_DNSPYTHON:
            return []
        results = []
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, len(self.candidates))) as ex:
            for ns, lat in zip(self.candidates,
                               ex.map(self._latency, self.candidates)):
                if lat is not None:
                    results.append((ns, lat))
        results.sort(key=lambda x: x[1])
        with self._lock:
            self.healthy = results[:self.keep]
            self._cycle = (itertools.cycle([ns for ns, _ in self.healthy])
                           if self.healthy else None)
        return self.healthy

    def get_resolver(self):
        """Returns (resolver, ns). Falls back to (system_resolver, None)."""
        with self._lock:
            if self._cycle:
                ns = next(self._cycle)
                return self._make(ns), ns
        return self._make(None), None      # system resolver fallback

    def mark_bad(self, ns):
        if ns is None:
            return
        with self._lock:
            self.healthy = [(n, l) for n, l in self.healthy if n != ns]
            self._cycle = (itertools.cycle([n for n, _ in self.healthy])
                           if self.healthy else None)
            thin = len(self.healthy) < max(3, self.keep // 3)
        if thin:
            self.benchmark()


# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION  (wordlist, ports, signatures, versions — carried from v3)
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_WORDLIST = [
    "www","www2","www3","web","web1","web2",
    "mail","mail1","mail2","smtp","pop","pop3","imap","ftp","sftp",
    "webmail","owa","exchange","autodiscover",
    "remote","vpn","vpn1","vpn2","rdp","rds","citrix","sslvpn",
    "api","api2","api3","api-v2","api-new","v2","v1","v3","rest","graphql","grpc",
    "admin","administrator","portal","panel","dashboard","manage","management",
    "cpanel","whm","plesk","backoffice",
    "dev","dev1","dev2","dev3","develop","development",
    "staging","stage","stg","stg1","stg2",
    "test","test1","test2","testing","qa","qa1","uat","preprod","sandbox",
    "prod","production","live",
    "dev-api","dev-portal","dev-admin","dev-app","dev-web","dev-b2b","dev-crm",
    "new-api","new-portal","new-admin","new-app","new-b2b",
    "old-portal","old-api","old-admin","test-api","test-portal","stage-api",
    "beta","beta2","alpha","next","rc","preview",
    "blog","forum","wiki","docs","documentation","kb","help","faq",
    "support","tickets","desk","helpdesk","service","servicedesk",
    "crm","erp","billing","invoice","finance","hr","hris",
    "b2b","b2c","cabinet","lk","office","corp","intranet","internal",
    "shop","store","cart","ecommerce","pay","payment","checkout","catalog",
    "cdn","static","assets","media","img","images","files","uploads",
    "upload","download","storage","s3","backup","minio","fileserver",
    "shared","share","nas","git","gitlab","svn","ci","cd","jenkins","gitea",
    "jira","confluence","bitbucket","redmine","registry","nexus","harbor",
    "docker","k8s","kube","monitor","monitoring","metrics","grafana","kibana",
    "prometheus","elastic","splunk","nagios","zabbix",
    "mx","mx1","mx2","ns","ns1","ns2","dns","dns1","dns2",
    "proxy","gateway","lb","waf","auth","sso","oauth","login","secure","id",
    "accounts","identity","keycloak","mobile","m","app","apps","ios","android",
    "cloud","aws","azure","gcp","db","database","mysql","postgres","redis",
    "mongo","phpmyadmin","adminer","chat","status","health","demo","poc","lab",
    "1","2","3","01","02","server","server1","host","node","node1",
]

RECURSIVE_PREFIXES = [
    "dev","dev1","dev2","test","stage","new","old","api","admin",
    "beta","rc","demo","preprod","backup",
]

COMMON_PORTS = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",587:"SMTP/TLS",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    5900:"VNC",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",
    8888:"HTTP-Dev",9200:"Elasticsearch",27017:"MongoDB",
}

SIGNAL_WEIGHTS = {
    "header_exact": 40, "header_prefix": 25, "body_specific": 20,
    "body_generic": 10, "cookie": 30,
}
DEFAULT_MIN_CONFIDENCE = 25

SERVICE_SIGNATURES: Dict[str, dict] = {
    "Bitrix24 / 1C-Bitrix": {"signals": [
        ("header_prefix","x-powered-cms: bitrix"),("body_specific","/bitrix/js/"),
        ("body_specific","BX.message"),("body_generic","bitrix24"),
        ("cookie","BITRIX_SM_"),("cookie","BX_")]},
    "Microsoft Exchange / OWA": {"signals": [
        ("header_exact","x-owa-version"),("header_exact","x-feserver"),
        ("body_specific","OutlookSession"),("body_specific","X-OWA-Version")]},
    "Microsoft Exchange ActiveSync": {"signals": [
        ("header_exact","ms-asprotocolversion")]},
    "WordPress": {"signals": [
        ("body_specific","/wp-content/themes/"),("body_specific","/wp-includes/js/"),
        ("body_specific","wp-json"),("body_generic","WordPress")]},
    "Joomla": {"signals": [
        ("body_specific","/components/com_"),("body_specific","/media/jui/"),
        ("body_generic","Joomla!")]},
    "Drupal": {"signals": [
        ("header_exact","x-drupal-cache"),("header_prefix","x-generator: drupal"),
        ("body_specific","/sites/default/files/"),("body_specific","Drupal.settings")]},
    "phpBB Forum": {"signals": [
        ("body_specific","Powered by phpBB"),("body_specific","phpBB Group"),
        ("body_generic","phpBB")]},
    "Confluence (Atlassian)": {"signals": [
        ("header_prefix","x-confluence-"),("body_specific","confluence-context-path"),
        ("body_generic","Confluence")]},
    "JIRA (Atlassian)": {"signals": [
        ("body_specific","Atlassian Jira"),("body_specific","jira-frontend"),
        ("body_generic","JIRA")]},
    "GitLab": {"signals": [
        ("header_prefix","x-gitlab-"),("body_specific","gl-logo"),
        ("body_specific","GitLab Community Edition"),("body_generic","GitLab")]},
    "Jenkins": {"signals": [
        ("header_exact","x-jenkins"),("header_exact","x-hudson"),
        ("body_specific","jenkins-head-css"),("body_generic","Jenkins")]},
    "cPanel": {"signals": [
        ("body_specific","cPanel, Inc."),("body_generic","cPanel"),
        ("body_generic","WHM")]},
    "Plesk": {"signals": [
        ("body_specific","plesk-ui-library"),("body_specific","plesk-icon"),
        ("body_generic","Plesk")]},
    "Grafana": {"signals": [
        ("header_prefix","x-grafana-"),("body_specific","grafana_session"),
        ("body_generic","Grafana")]},
    "Kibana": {"signals": [
        ("body_specific","kbn-injected-metadata"),("body_specific","kbnVersion"),
        ("body_generic","Kibana")]},
    "Roundcube Webmail": {"signals": [
        ("body_specific","roundcube_sessid"),("body_specific","rcmloginuser"),
        ("body_generic","Roundcube")]},
    "Nextcloud / ownCloud": {"signals": [
        ("body_specific","oc_sessionPassphrase"),("body_specific","nextcloud-icon"),
        ("body_generic","Nextcloud")]},
    "Keycloak (SSO)": {"signals": [
        ("body_specific","keycloak-session"),("body_specific","kc-logo-text"),
        ("body_generic","Keycloak")]},
    "SonarQube": {"signals": [
        ("body_specific","sonarqube-logo"),("body_generic","SonarQube")]},
    "Zabbix": {"signals": [
        ("body_specific","zabbix.php"),("body_specific","zbx_sessionid"),
        ("body_generic","Zabbix")]},
    "phpMyAdmin": {"signals": [
        ("body_specific","phpMyAdmin"),("body_specific","pma_absolute_uri"),
        ("cookie","phpMyAdmin")]},
    "Adminer": {"signals": [
        ("body_specific","adminer.org"),("body_generic","Adminer")]},
    "Apache Tomcat": {"signals": [
        ("body_specific","Apache Tomcat"),("body_specific","Tomcat Documentation"),
        ("header_prefix","x-powered-by: servlet")]},
    "IIS": {"signals": [
        ("header_exact","server: microsoft-iis"),("body_specific","IIS Windows Server")]},
    "nginx": {"signals": [("header_exact","server: nginx")]},
    "Apache httpd": {"signals": [("header_exact","server: apache")]},
    "Traefik": {"signals": [
        ("header_prefix","x-powered-by: traefik"),("body_specific","Traefik")]},
    "Varnish Cache": {"signals": [
        ("header_exact","x-varnish"),("header_prefix","via: varnish")]},
    "Shopify": {"signals": [
        ("header_prefix","x-shopify-"),("body_specific","cdn.shopify.com"),
        ("body_generic","Shopify")]},
    "Laravel (PHP)": {"signals": [
        ("cookie","laravel_session"),("body_specific","laravel_token"),
        ("body_generic","Laravel")]},
    "Django (Python)": {"signals": [
        ("cookie","csrftoken"),("body_specific","csrfmiddlewaretoken"),
        ("body_generic","Django")]},
    "Ruby on Rails": {"signals": [
        ("header_exact","x-runtime"),("header_prefix","x-powered-by: phusion passenger")]},
    "ASP.NET": {"signals": [
        ("header_exact","x-aspnet-version"),("header_exact","x-aspnetmvc-version"),
        ("header_prefix","x-powered-by: asp.net"),("cookie","asp.net_sessionid"),
        ("cookie",".aspxauth")]},
    "Node.js / Express": {"signals": [("header_exact","x-powered-by: express")]},
    "Mikrotik RouterOS": {"signals": [
        ("body_specific","RouterOS"),("body_specific","MikroTik")]},
    "Fortinet / FortiGate": {"signals": [
        ("header_exact","server: fortigate"),("body_specific","FortiGate")]},
    "Elasticsearch": {"signals": [
        ("body_specific",'"cluster_name"'),("body_specific",'"cluster_uuid"')]},
    "MinIO": {"signals": [
        ("body_specific","minio-logo"),("body_generic","MinIO")]},
    "Prometheus": {"signals": [
        ("body_specific","prometheus_build_info"),("body_generic","Prometheus")]},
    "Vault (HashiCorp)": {"signals": [
        ("body_specific","vault-logo"),("body_generic","Vault")]},
    "Kubernetes Dashboard": {"signals": [
        ("body_specific","kube-dashboard"),("body_generic","Kubernetes")]},
}

WAF_SIGNATURES: Dict[str, Tuple] = {
    "Cloudflare":        (lambda h,b,c: "cf-ray" in h or h.get("server","").lower().startswith("cloudflare"), 95),
    "AWS WAF / Shield":  (lambda h,b,c: "x-amzn-requestid" in h or "x-amz-cf-id" in h, 85),
    "Akamai":            (lambda h,b,c: "x-akamai-transformed" in h or "x-check-cacheable" in h, 90),
    "Fastly":            (lambda h,b,c: "x-served-by" in h and "cache-" in h.get("x-served-by","").lower(), 85),
    "Imperva Incapsula": (lambda h,b,c: "x-iinfo" in h or "visid_incap" in c, 90),
    "Sucuri":            (lambda h,b,c: "x-sucuri-id" in h or "sucuri-cloudproxy" in h.get("server","").lower(), 90),
    "F5 BIG-IP ASM":     (lambda h,b,c: "bigipserver" in c or "ts_" in c, 80),
    "Barracuda WAF":     (lambda h,b,c: "barra_counter_session" in c, 85),
    "ModSecurity":       (lambda h,b,c: "mod_security" in b or "modsecurity" in h.get("server","").lower(), 75),
    "DDoS-Guard":        (lambda h,b,c: "ddos-guard" in h.get("server","").lower(), 90),
    "Qrator":            (lambda h,b,c: "x-qrator-" in " ".join(h.keys()), 85),
}

# CDN hints from headers (separate from WAF)
CDN_HINTS = {
    "Cloudflare": ["cf-ray", "cf-cache-status"],
    "Fastly":     ["x-served-by", "x-fastly"],
    "CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "Akamai":     ["x-akamai-transformed", "akamai-grn"],
    "Google":     ["x-goog-", "via: 1.1 google"],
}

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
]

VERSION_PATTERNS = [
    (r"(?i)Apache/(\d+\.\d+[\.\d]*)","Apache","any"),
    (r"(?i)nginx/(\d+\.\d+[\.\d]*)","nginx","any"),
    (r"(?i)Microsoft-IIS/(\d+\.\d+)","IIS","any"),
    (r"(?i)LiteSpeed/?([\d.]+)?","LiteSpeed","server"),
    (r"(?i)openresty/([\d.]+)","OpenResty","server"),
    (r"(?i)PHP/(\d+\.\d+[\.\d]*)","PHP","any"),
    (r"(?i)OpenSSL/(\d+[\.\d\w]*)","OpenSSL","any"),
    (r"(?i)Python/(\d+\.\d+[\.\d]*)","Python","server"),
    (r"(?i)Node\.?js[/ v]*([\d.]+)","Node.js","any"),
    (r"(?i)WordPress[/ ](\d+\.\d+[\.\d]*)","WordPress","any"),
    (r"(?i)<meta[^>]+generator[^>]+WordPress (\d+\.\d+[\.\d]*)","WordPress","body"),
    (r"(?i)Drupal (\d+\.?\d*)","Drupal","any"),
    (r"(?i)Joomla[! /]?(\d+\.\d+)","Joomla","any"),
    (r"(?i)1C-Bitrix[/ ]?([\d.]+)?","1C-Bitrix","any"),
    (r"(?i)Tomcat/(\d+\.\d+[\.\d]*)","Tomcat","any"),
    (r"(?i)Gunicorn/(\d+\.\d+[\.\d]*)","Gunicorn","server"),
    (r"(?i)redis_version[\":\s]+([\d.]+)","Redis","body"),
    (r"(?i)Elasticsearch[\"/ ]([\d.]+)","Elasticsearch","body"),
    (r"(?i)Nextcloud[/ ]?([\d.]+)?","Nextcloud","body"),
    (r"(?i)GitLab[/ ]?([\d.]+)?","GitLab","body"),
    (r"(?i)Jenkins[/ ]?([\d.]+)?","Jenkins","body"),
    (r"(?i)Grafana[/ v]*([\d.]+)","Grafana","body"),
    (r"(?i)Keycloak[/ ]?([\d.]+)?","Keycloak","body"),
    (r"(?i)Bootstrap[/ ](\d+\.\d+[\.\d]*)","Bootstrap","body"),
    (r"(?i)jQuery[/ v]*(\d+\.\d+[\.\d]*)","jQuery","body"),
    (r"(?i)React[/ ](\d+\.\d+[\.\d]*)","React","body"),
    (r"(?i)Vue[. /](\d+\.\d+[\.\d]*)","Vue.js","body"),
    (r"(?i)Angular[/ ](\d+\.\d+[\.\d]*)","Angular","body"),
]


def extract_versions(body: str, server_header: str = "", powered_header: str = "") -> list:
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
                found.setdefault(tech, f"{tech}/{ver}" if ver else tech)
                break
    return list(found.values())


# ═══════════════════════════════════════════════════════════════════════════════
#  JS RECON — endpoint / new-host / cloud-asset extraction
# ═══════════════════════════════════════════════════════════════════════════════

_JS_URL_RE     = re.compile(r"""https?://[^\s"'`<>()\\{}]+""")
_JS_WS_RE      = re.compile(r"""wss?://[^\s"'`<>()\\{}]+""")
_JS_PATH_RE    = re.compile(r"""["'`](/[a-zA-Z0-9_\-./]{2,}?)["'`]""")
_JS_S3_RE      = re.compile(r"""[a-z0-9.\-]+\.s3[.\-][a-z0-9\-]*\.amazonaws\.com""", re.I)
_JS_FIREBASE_RE= re.compile(r"""[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)""", re.I)
_JS_AZURE_RE   = re.compile(r"""[a-z0-9]+\.blob\.core\.windows\.net""", re.I)
_JS_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)

_API_HINTS = ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest", "/auth",
              "/oauth", "/token", "/swagger", "/openapi", "/api-docs",
              ".json", "/gql", "/rpc", "/internal", "/admin")


def host_in_domain(host: str, domain: str) -> bool:
    host = host.lower().strip().strip(".")
    return host == domain or host.endswith("." + domain)


def extract_js_intel(text: str, domain: str) -> dict:
    """Extract intel from a JS/HTML body. Returns sets of findings."""
    out = {"hosts": set(), "urls": set(), "apis": set(),
           "ws": set(), "cloud": set()}
    if not text:
        return out

    for m in _JS_URL_RE.findall(text):
        url = m.rstrip('",);')
        out["urls"].add(url)
        h = (urlparse(url).hostname or "").lower()
        if h and host_in_domain(h, domain):
            out["hosts"].add(h)

    for m in _JS_WS_RE.findall(text):
        out["ws"].add(m.rstrip('",);'))

    for m in _JS_PATH_RE.findall(text):
        low = m.lower()
        if any(hint in low for hint in _API_HINTS):
            out["apis"].add(m)

    for rx in (_JS_S3_RE, _JS_FIREBASE_RE, _JS_AZURE_RE):
        for m in rx.findall(text):
            out["cloud"].add(m.lower())

    # bare host mentions of the target domain (e.g. "internal-api.example.com")
    for m in re.findall(r"""([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9\-]+)*\.""" +
                        re.escape(domain) + r""")""", text, re.I):
        out["hosts"].add(m.lower().strip("."))

    return out


def script_srcs(html: str) -> list:
    return _JS_SCRIPT_SRC.findall(html or "")


# ═══════════════════════════════════════════════════════════════════════════════
#  SYNC HTTP (retry) — used by threaded reverse-IP / misc
# ═══════════════════════════════════════════════════════════════════════════════

def http_get_retry(url, timeout=6, retries=3, headers=None):
    if not HAS_REQUESTS:
        return None
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    proxies = None
    conn, per = _PROXY
    if per:
        proxies = {"http": per, "https": per}
    for attempt in range(retries):
        try:
            return requests.get(url, timeout=timeout, verify=False,
                                allow_redirects=True, headers=h, proxies=proxies)
        except requests.exceptions.ConnectionError:
            break
        except Exception:
            if attempt < retries - 1:
                time.sleep(0.5 * (2 ** attempt))
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  ASYNC HTTP helpers (proxy + rate-limit aware)
# ═══════════════════════════════════════════════════════════════════════════════

def make_connector(limit=50):
    conn_url, _ = _PROXY
    if conn_url and HAS_AIOHTTP_SOCKS:
        try:
            return ProxyConnector.from_url(conn_url, ssl=False, limit=limit)
        except Exception:
            pass
    return aiohttp.TCPConnector(limit=limit, ssl=False, ttl_dns_cache=300)


async def async_get(session, url, rl_key=None, want="both", **kw):
    """Async GET with retry, optional per-source rate limit, proxy passthrough.
    want: 'json' | 'text' | 'both' -> returns dict {json,text,status,headers,cookies}."""
    global _RL
    _, per_proxy = _PROXY
    if per_proxy and "proxy" not in kw:
        kw["proxy"] = per_proxy
    for attempt in range(3):
        if _RL and rl_key:
            await _RL.acquire(rl_key)
        try:
            async with session.get(url, ssl=False, allow_redirects=True, **kw) as resp:
                text = await resp.text(errors="replace")
                data = None
                if want in ("json", "both"):
                    try:
                        data = json.loads(text)
                    except Exception:
                        data = None
                return {"json": data, "text": text, "status": resp.status,
                        "headers": {k.lower(): v for k, v in resp.headers.items()},
                        "cookies": " ".join(c.key.lower()
                                            for c in resp.cookies.values()),
                        "url": str(resp.url)}
        except Exception:
            if attempt < 2:
                await asyncio.sleep(0.5 * (2 ** attempt))
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS RESOLUTION + RECORDS + DNSSEC
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_hostname(hostname: str) -> dict:
    result = {"hostname": hostname, "ips": [], "ipv6": [], "cname": None, "alive": False}
    if HAS_DNSPYTHON and _POOL:
        resolver, ns = _POOL.get_resolver()
        if resolver is not None:
            for rtype, key in (("A", "ips"), ("AAAA", "ipv6")):
                try:
                    ans = resolver.resolve(hostname, rtype)
                    result[key] = [r.address for r in ans]
                    result["alive"] = True
                except dns.exception.Timeout:
                    _POOL.mark_bad(ns)
                except Exception:
                    pass
            try:
                ans = resolver.resolve(hostname, "CNAME")
                result["cname"] = str(ans[0].target)
            except Exception:
                pass
            return result
    # fallback: system getaddrinfo
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


def get_dns_records(hostname: str) -> dict:
    """MX / NS / TXT / SOA + DNSSEC presence. Best-effort."""
    rec = {"mx": [], "ns": [], "txt": [], "soa": None, "dnssec": False}
    if not (HAS_DNSPYTHON and _POOL):
        return rec
    resolver, ns = _POOL.get_resolver()
    if resolver is None:
        return rec
    def q(t):
        try:
            return list(resolver.resolve(hostname, t))
        except Exception:
            return []
    rec["mx"]  = sorted(f"{r.preference} {r.exchange}" for r in q("MX"))
    rec["ns"]  = sorted(str(r.target) for r in q("NS"))
    rec["txt"] = [b" ".join(r.strings).decode("utf-8", "replace") for r in q("TXT")]
    soa = q("SOA")
    if soa:
        rec["soa"] = str(soa[0].mname)
    rec["dnssec"] = bool(q("DNSKEY"))
    return rec


def get_ptr(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  WILDCARD DETECTION  (multi-probe)
# ═══════════════════════════════════════════════════════════════════════════════

def detect_wildcard(domain: str, probes: int = 3) -> Optional[set]:
    seen_ips = []
    alive = 0
    for _ in range(probes):
        rand = ''.join(random.choices(string.ascii_lowercase, k=12))
        r = resolve_hostname(f"{rand}.{domain}")
        if r["alive"]:
            alive += 1
            seen_ips.append(set(r["ips"] + r["ipv6"]))
    if alive < 2:
        return None
    common = set.intersection(*seen_ips) if seen_ips else set()
    union  = set().union(*seen_ips) if seen_ips else set()
    # return common IPs if stable, else the union (round-robin wildcard)
    return common or union or None


# ═══════════════════════════════════════════════════════════════════════════════
#  TLS INFO (cert issuer / expiry / SANs)
# ═══════════════════════════════════════════════════════════════════════════════

def get_tls_info(hostname: str, timeout: float = 5) -> dict:
    info = {"sans": set(), "issuer": None, "not_after": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        for typ, val in cert.get("subjectAltName", []):
            if typ == "DNS":
                info["sans"].add(val.lower().lstrip("*."))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        info["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
        info["not_after"] = cert.get("notAfter")
    except Exception:
        pass
    return info


# ═══════════════════════════════════════════════════════════════════════════════
#  PORT SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

def scan_port(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_ports(host, ports, timeout=1.5):
    open_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(30, len(ports))) as ex:
        fmap = {ex.submit(scan_port, host, p, timeout): (p, s) for p, s in ports.items()}
        for fut in concurrent.futures.as_completed(fmap):
            p, s = fmap[fut]
            if fut.result():
                open_ports[p] = s
    return open_ports


# ═══════════════════════════════════════════════════════════════════════════════
#  PASSIVE SOURCES (async, rate-limited, defensive)
# ═══════════════════════════════════════════════════════════════════════════════

def _host_filter(names, domain):
    out = set()
    for n in names:
        n = (n or "").strip().lower().lstrip("*.")
        if host_in_domain(n, domain):
            out.add(n)
    return out


async def _src_crtsh(s, d):
    r = await async_get(s, f"https://crt.sh/?q=%.{d}&output=json",
                        rl_key="crtsh", timeout=aiohttp.ClientTimeout(total=30))
    if r and r["json"]:
        names = []
        for e in r["json"]:
            names += e.get("name_value", "").splitlines()
        return _host_filter(names, d)
    return set()

async def _src_hackertarget(s, d):
    r = await async_get(s, f"https://api.hackertarget.com/hostsearch/?q={d}",
                        rl_key="hackertarget", want="text",
                        timeout=aiohttp.ClientTimeout(total=15))
    if r and r["text"] and "API count exceeded" not in r["text"]:
        return _host_filter((l.split(",")[0] for l in r["text"].splitlines()), d)
    return set()

async def _src_alienvault(s, d):
    r = await async_get(
        s, f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
        rl_key="alienvault", timeout=aiohttp.ClientTimeout(total=15))
    if r and r["json"]:
        return _host_filter((rec.get("hostname", "")
                             for rec in r["json"].get("passive_dns", [])), d)
    return set()

async def _src_rapiddns(s, d):
    r = await async_get(s, f"https://rapiddns.io/subdomain/{d}?full=1",
                        rl_key="rapiddns", want="text",
                        timeout=aiohttp.ClientTimeout(total=15))
    if r and r["text"]:
        pat = r'<td>([a-zA-Z0-9._-]+\.' + re.escape(d) + r')</td>'
        return _host_filter(re.findall(pat, r["text"]), d)
    return set()

async def _src_urlscan(s, d):
    r = await async_get(s, f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=200",
                        rl_key="urlscan", timeout=aiohttp.ClientTimeout(total=15))
    if r and r["json"]:
        return _host_filter((res.get("page", {}).get("domain", "")
                             for res in r["json"].get("results", [])), d)
    return set()

async def _src_anubis(s, d):
    r = await async_get(s, f"https://jldc.me/anubis/subdomains/{d}",
                        rl_key="anubis", timeout=aiohttp.ClientTimeout(total=12))
    if r and isinstance(r["json"], list):
        return _host_filter(r["json"], d)
    return set()

async def _src_webarchive(s, d):
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{d}/*"
           f"&output=json&fl=original&collapse=urlkey&limit=500")
    r = await async_get(s, url, rl_key="webarchive",
                        timeout=aiohttp.ClientTimeout(total=25))
    subs = set()
    if r and isinstance(r["json"], list):
        for row in r["json"][1:]:
            if row:
                h = (urlparse(row[0]).hostname or "")
                if host_in_domain(h, d):
                    subs.add(h.lower())
    return subs

async def _src_certspotter(s, d):
    r = await async_get(
        s, f"https://api.certspotter.com/v1/issuances?domain={d}"
           f"&include_subdomains=true&expand=dns_names",
        rl_key="certspotter", timeout=aiohttp.ClientTimeout(total=15))
    subs = set()
    if r and isinstance(r["json"], list):
        for e in r["json"]:
            subs |= _host_filter(e.get("dns_names", []), d)
    return subs

async def _src_virustotal(s, d, key):
    if not key:
        return set()
    subs, url = set(), \
        f"https://www.virustotal.com/api/v3/domains/{d}/subdomains?limit=40"
    while url:
        r = await async_get(s, url, rl_key="virustotal",
                            headers={"x-apikey": key},
                            timeout=aiohttp.ClientTimeout(total=15))
        if not r or not r["json"]:
            break
        subs |= _host_filter((i.get("id", "") for i in r["json"].get("data", [])), d)
        url = r["json"].get("links", {}).get("next")
    return subs

async def _src_securitytrails(s, d, key):
    if not key:
        return set()
    r = await async_get(s, f"https://api.securitytrails.com/v1/domain/{d}/subdomains",
                        rl_key="securitytrails", headers={"apikey": key},
                        timeout=aiohttp.ClientTimeout(total=15))
    if r and r["json"]:
        return {f"{sub}.{d}" for sub in r["json"].get("subdomains", [])}
    return set()

async def _src_shodan_dns(s, d, key):
    if not key:
        return set()
    r = await async_get(s, f"https://api.shodan.io/dns/domain/{d}?key={key}",
                        rl_key="shodan", timeout=aiohttp.ClientTimeout(total=15))
    if r and r["json"]:
        return {f"{sub}.{d}" for sub in r["json"].get("subdomains", [])}
    return set()

async def _src_chaos(s, d, key):
    # ProjectDiscovery Chaos. Endpoint/headers may evolve — kept defensive.
    if not key:
        return set()
    r = await async_get(s, f"https://dns.projectdiscovery.io/dns/{d}/subdomains",
                        rl_key="chaos", headers={"Authorization": key},
                        timeout=aiohttp.ClientTimeout(total=20))
    if r and r["json"]:
        subs = r["json"].get("subdomains", [])
        return {f"{x}.{d}" for x in subs if x}
    return set()

async def _src_censys(s, d, cid, csecret):
    # Censys v2 hosts search. Endpoint may need adjustment for your plan.
    if not (cid and csecret):
        return set()
    import base64
    auth = base64.b64encode(f"{cid}:{csecret}".encode()).decode()
    r = await async_get(
        s, f"https://search.censys.io/api/v2/hosts/search?q={d}&per_page=100",
        rl_key="censys", headers={"Authorization": f"Basic {auth}"},
        timeout=aiohttp.ClientTimeout(total=20))
    subs = set()
    if r and r["json"]:
        try:
            for hit in r["json"].get("result", {}).get("hits", []):
                for name in hit.get("dns", {}).get("names", []) or []:
                    if host_in_domain(name, d):
                        subs.add(name.lower())
                for name in hit.get("names", []) or []:
                    if host_in_domain(name, d):
                        subs.add(name.lower())
        except Exception:
            pass
    return subs

async def _src_github(s, d, token):
    # GitHub code search for the domain. Best-effort text grep of fragments.
    if not token:
        return set()
    subs, pat = set(), re.compile(
        r"([a-z0-9][a-z0-9\-.]*\." + re.escape(d) + r")", re.I)
    for page in range(1, 4):
        r = await async_get(
            s, f"https://api.github.com/search/code?q=%22{d}%22&per_page=100&page={page}",
            rl_key="github",
            headers={"Authorization": f"token {token}",
                     "Accept": "application/vnd.github.v3.text-match+json"},
            timeout=aiohttp.ClientTimeout(total=20))
        if not r or not r["json"]:
            break
        items = r["json"].get("items", [])
        if not items:
            break
        for it in items:
            for m in it.get("text_matches", []):
                subs |= _host_filter(pat.findall(m.get("fragment", "")), d)
    return subs


async def fetch_passive_sources_async(domain, keys: dict) -> dict:
    if not HAS_AIOHTTP:
        return {}
    connector = make_connector(limit=10)
    results = {}
    async with aiohttp.ClientSession(connector=connector,
                                     headers={"User-Agent": UA}) as s:
        tasks = {
            "crt.sh": _src_crtsh(s, domain), "HackerTarget": _src_hackertarget(s, domain),
            "AlienVault OTX": _src_alienvault(s, domain), "RapidDNS": _src_rapiddns(s, domain),
            "URLScan": _src_urlscan(s, domain), "Anubis-DB": _src_anubis(s, domain),
            "WebArchive": _src_webarchive(s, domain), "CertSpotter": _src_certspotter(s, domain),
        }
        if keys.get("vt"):      tasks["VirusTotal"] = _src_virustotal(s, domain, keys["vt"])
        if keys.get("st"):      tasks["SecurityTrails"] = _src_securitytrails(s, domain, keys["st"])
        if keys.get("shodan"):  tasks["Shodan DNS"] = _src_shodan_dns(s, domain, keys["shodan"])
        if keys.get("chaos"):   tasks["Chaos"] = _src_chaos(s, domain, keys["chaos"])
        if keys.get("censys_id"):
            tasks["Censys"] = _src_censys(s, domain, keys["censys_id"], keys.get("censys_secret", ""))
        if keys.get("github"):  tasks["GitHub"] = _src_github(s, domain, keys["github"])

        gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, res in zip(tasks.keys(), gathered):
            results[name] = set() if isinstance(res, Exception) else (res or set())
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  ENRICHMENT (geo/ASN via ip-api, Shodan host) — async + rate-limited
# ═══════════════════════════════════════════════════════════════════════════════

_ip_info_cache: Dict[str, dict] = {}

async def enrich_ip_async(session, ip: str) -> dict:
    info = {"asn": None, "asn_org": None, "country": None, "city": None}
    if not ip or ip.startswith(("10.", "192.168.", "127.", "::1")):
        return info
    if ip in _ip_info_cache:
        return _ip_info_cache[ip]
    r = await async_get(
        session, f"http://ip-api.com/json/{ip}?fields=country,city,isp,as",
        rl_key="ip-api", timeout=aiohttp.ClientTimeout(total=6))
    if r and r["json"]:
        d = r["json"]
        info["country"] = d.get("country")
        info["city"]    = d.get("city")
        info["asn_org"] = d.get("isp") or d.get("as")
    _ip_info_cache[ip] = info
    return info

async def enrich_shodan_async(session, ip: str, key: str) -> dict:
    info = {"ports": [], "vulns": [], "tags": []}
    if not key or not ip:
        return info
    r = await async_get(session, f"https://api.shodan.io/shodan/host/{ip}?key={key}",
                        rl_key="shodan", timeout=aiohttp.ClientTimeout(total=10))
    if r and r["json"]:
        d = r["json"]
        info["ports"] = d.get("ports", [])
        info["vulns"] = list(d.get("vulns", {}).keys())
        info["tags"]  = d.get("tags", [])
    return info


# ═══════════════════════════════════════════════════════════════════════════════
#  FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════

def score_service(sigs, h_lower, body_low, cookies) -> int:
    total = sum(SIGNAL_WEIGHTS.get(t, 10) for t, _ in sigs.get("signals", []))
    if total == 0:
        return 0
    matched = 0
    for sig_type, sig_val in sigs.get("signals", []):
        sv = sig_val.lower(); ok = False
        if sig_type in ("header_exact", "header_prefix"):
            key, _, val = sv.partition(":")
            key = key.strip(); val = val.strip()
            ok = (key in h_lower and val in h_lower[key].lower()) if val \
                else any(key in hk for hk in h_lower)
        elif sig_type in ("body_specific", "body_generic"):
            ok = sv in body_low
        elif sig_type == "cookie":
            ok = sv in cookies
        if ok:
            matched += SIGNAL_WEIGHTS.get(sig_type, 10)
    return min(100, round(matched / max(total, 1) * 100))


def detect_waf(h_lower, body_low, cookies):
    for name, (fn, conf) in WAF_SIGNATURES.items():
        try:
            if fn(h_lower, body_low, cookies):
                return (name, conf)
        except Exception:
            pass
    return None


def detect_cdn(h_lower) -> Optional[str]:
    joined = " ".join(f"{k}: {v}" for k, v in h_lower.items()).lower()
    for cdn, hints in CDN_HINTS.items():
        if any(hint in joined for hint in hints):
            return cdn
    return None


def missing_security_headers(h_lower) -> list:
    return [h for h in SECURITY_HEADERS if h not in h_lower]


def fingerprint_from_ctx(ctx, min_conf) -> dict:
    out = {"services": [], "title": ctx["title"], "server": ctx["server"] or None,
           "powered": ctx["powered"] or None, "waf": None, "waf_confidence": 0,
           "versions": [], "status": ctx["status"], "cdn": None,
           "missing_sec": [], "redirected_to": ctx.get("final_url")}
    waf = detect_waf(ctx["h_lower"], ctx["body_low"], ctx["cookies"])
    if waf:
        out["waf"], out["waf_confidence"] = waf
    out["cdn"] = detect_cdn(ctx["h_lower"])
    out["missing_sec"] = missing_security_headers(ctx["h_lower"])
    out["versions"] = extract_versions(ctx["body_full"][:10000], ctx["server"], ctx["powered"])
    server_raw = (ctx.get("server") or "").strip()
    if server_raw and not any(server_raw.lower().split("/")[0] in v.lower()
                              for v in out["versions"]):
        out["versions"].insert(0, server_raw)
    for name, sigs in SERVICE_SIGNATURES.items():
        sc = score_service(sigs, ctx["h_lower"], ctx["body_low"], ctx["cookies"])
        if sc >= min_conf:
            out["services"].append((name, sc))
    out["services"].sort(key=lambda x: -x[1])
    return out


def _ctx_from_resp(headers, cookies, text, status, final_url):
    tm = re.search(r"<title[^>]*>([^<]{1,120})</title>", text or "", re.I)
    return {"h_lower": headers, "cookies": cookies, "body_full": text or "",
            "body_low": (text or "")[:12000].lower(),
            "server": headers.get("server", ""), "powered": headers.get("x-powered-by", ""),
            "title": tm.group(1).strip() if tm else None,
            "status": status, "final_url": final_url}


async def fingerprint_host_async(session, hostname, open_ports, min_conf, domain,
                                  do_js: bool) -> dict:
    empty = {"services": [], "title": None, "server": None, "powered": None,
             "waf": None, "waf_confidence": 0, "versions": [], "status": None,
             "cdn": None, "missing_sec": [], "redirected_to": None,
             "js_intel": {"hosts": [], "apis": [], "ws": [], "cloud": []}}
    urls = []
    if 443 in open_ports:  urls.append(f"https://{hostname}/")
    if 8443 in open_ports: urls.append(f"https://{hostname}:8443/")
    if 80 in open_ports:   urls.append(f"http://{hostname}/")
    if 8080 in open_ports: urls.append(f"http://{hostname}:8080/")
    if not urls:
        urls = [f"https://{hostname}/", f"http://{hostname}/"]

    result, html = None, ""
    for base in urls[:2]:
        r = await async_get(session, base, timeout=aiohttp.ClientTimeout(total=8, connect=4))
        if r:
            ctx = _ctx_from_resp(r["headers"], r["cookies"], r["text"],
                                 r["status"], r["url"])
            result = fingerprint_from_ctx(ctx, min_conf)
            html = r["text"] or ""
            break
    if result is None:
        return empty

    intel = {"hosts": set(), "apis": set(), "ws": set(), "cloud": set()}
    if do_js and html:
        page_intel = extract_js_intel(html, domain)
        for k in intel:
            intel[k] |= page_intel.get(k, set())
        # fetch same-origin JS files
        srcs = script_srcs(html)[:12]
        base_url = urls[0]
        js_tasks = []
        for src in srcs:
            ju = urljoin(base_url, src)
            if host_in_domain(urlparse(ju).hostname or "", domain):
                js_tasks.append(async_get(session, ju, want="text",
                                          timeout=aiohttp.ClientTimeout(total=8)))
        for jr in await asyncio.gather(*js_tasks, return_exceptions=True):
            if isinstance(jr, dict) and jr and jr["text"]:
                pi = extract_js_intel(jr["text"], domain)
                for k in intel:
                    intel[k] |= pi.get(k, set())

    result["js_intel"] = {k: sorted(v) for k, v in intel.items()}
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ASYNC PHASE: fingerprint + enrich all resolved hosts
# ═══════════════════════════════════════════════════════════════════════════════

async def process_hosts_async(hosts, min_conf, domain, do_js, shodan_key, no_osint):
    if not HAS_AIOHTTP:
        return {}
    connector = make_connector(limit=50)
    out = {}
    async with aiohttp.ClientSession(connector=connector,
                                     headers={"User-Agent": UA}) as s:
        sem = asyncio.Semaphore(40)

        async def task(h):
            async with sem:
                name = h["hostname"]
                fp = await fingerprint_host_async(
                    s, name, h.get("open_ports", {}), min_conf, domain, do_js)
                primary = h["ips"][0] if h.get("ips") else ""
                if not no_osint and primary:
                    fp["ip_info"] = await enrich_ip_async(s, primary)
                else:
                    fp["ip_info"] = {}
                fp["shodan"] = await enrich_shodan_async(s, primary, shodan_key) \
                    if shodan_key and primary else {}
                out[name] = fp

        await asyncio.gather(*[task(h) for h in hosts], return_exceptions=True)
    return out


# ═══════════════════════════════════════════════════════════════════════════════
#  BRUTEFORCE (threaded, resolver-pool aware)
# ═══════════════════════════════════════════════════════════════════════════════

def _check_host(hostname, wildcard_ips):
    info = resolve_hostname(hostname)
    if not info["alive"]:
        return None
    if wildcard_ips:
        host_ips = set(info["ips"] + info["ipv6"])
        if host_ips and host_ips.issubset(wildcard_ips):
            return None
    return hostname


def bruteforce_subdomains(domain, wordlist, threads, wildcard_ips=None, recursive=True):
    found_l1 = set()
    cprint(C.BLU, f"\n  ▸ Bruteforce L1: {len(wordlist)} words, {threads} threads…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        candidates = [f"{w}.{domain}" for w in wordlist]
        for res in ex.map(lambda h: _check_host(h, wildcard_ips), candidates):
            if res:
                found_l1.add(res); status("+", res, C.GRN)
    if not recursive or not found_l1:
        return found_l1
    rec = set()
    for host in found_l1:
        base = host[:-len(domain) - 1].split(".")[0]
        for pfx in RECURSIVE_PREFIXES:
            rec.add(f"{pfx}.{host}")
            rec.add(f"{pfx}-{base}.{domain}")
    rec -= (set(f"{w}.{domain}" for w in wordlist) | found_l1)
    found_l2 = set()
    if rec:
        cprint(C.BLU, f"  ▸ Bruteforce recursive: {len(rec)} candidates…")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for res in ex.map(lambda h: _check_host(h, wildcard_ips), sorted(rec)):
                if res:
                    found_l2.add(res); status("+", f"{res}  [recursive]", C.YLW)
    return found_l1 | found_l2


# ═══════════════════════════════════════════════════════════════════════════════
#  REVERSE IP (passive, report-only — never auto-scanned)
# ═══════════════════════════════════════════════════════════════════════════════

def reverse_ip_lookup(ip: str) -> set:
    hosts = set()
    r = http_get_retry(f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                       timeout=10, retries=2)
    if r and r.ok and "error" not in r.text.lower() and "API count" not in r.text:
        for line in r.text.splitlines():
            h = line.strip().lower()
            if h and "." in h:
                hosts.add(h)
    return hosts


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS-ONLY PHASE (threaded): resolve + ports + PTR + DNS records
# ═══════════════════════════════════════════════════════════════════════════════

def recon_dns_only(hostname, scan_ports_flag, timeout, dns_records=False):
    result = {"hostname": hostname, "ips": [], "ipv6": [], "ptr": [], "cname": None,
              "open_ports": {}, "dns_records": {}, "tls": {}, "shodan": {},
              "ip_info": {}, "services": [], "title": None, "server": None,
              "powered": None, "waf": None, "waf_confidence": 0, "cdn": None,
              "missing_sec": [], "versions": [], "http_status": None,
              "redirected_to": None, "service_scores": {}, "js_intel": {}, "errors": []}
    dns_info = resolve_hostname(hostname)
    result["ips"], result["ipv6"], result["cname"] = \
        dns_info["ips"], dns_info["ipv6"], dns_info["cname"]
    if not dns_info["alive"]:
        result["errors"].append("DNS resolution failed")
        return result
    for ip in result["ips"][:2]:
        ptr = get_ptr(ip)
        if ptr:
            result["ptr"].append(ptr)
    primary = result["ips"][0] if result["ips"] else ""
    if scan_ports_flag and primary:
        result["open_ports"] = scan_ports(primary, COMMON_PORTS, timeout)
    if dns_records:
        result["dns_records"] = get_dns_records(hostname)
    result["tls"] = get_tls_info(hostname)
    return result


def apply_fp_results(results, fp_map):
    for r in results:
        fp = fp_map.get(r["hostname"])
        if not fp:
            continue
        r["services"]       = [s for s, _ in fp["services"]]
        r["service_scores"] = {s: sc for s, sc in fp["services"]}
        r["title"]          = fp["title"]
        r["server"]         = fp["server"]
        r["powered"]        = fp["powered"]
        r["waf"]            = fp["waf"]
        r["waf_confidence"] = fp["waf_confidence"]
        r["cdn"]            = fp["cdn"]
        r["missing_sec"]    = fp["missing_sec"]
        r["versions"]       = fp["versions"]
        r["http_status"]    = fp["status"]
        r["redirected_to"]  = fp.get("redirected_to")
        r["js_intel"]       = fp.get("js_intel", {})
        if fp.get("ip_info"):
            r["ip_info"] = fp["ip_info"]
        if fp.get("shodan"):
            r["shodan"] = fp["shodan"]


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORTS
# ═══════════════════════════════════════════════════════════════════════════════

def _tech_string(r):
    parts = list(r.get("versions", []))
    scores = r.get("service_scores", {})
    generic = {"nginx", "Apache httpd", "IIS", "LiteSpeed", "OpenResty"}
    for svc in r.get("services", []):
        if svc in generic:
            continue
        sc = scores.get(svc, 0)
        parts.append(f"{svc} ({sc}%)" if sc else svc)
    return ", ".join(parts) if parts else "—"


TXT_TEMPLATE = """\
╔══════════════════════════════════════════════════════════════════════════════╗
║                     SubRecon v4 — Recon Report                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Target Domain  : {domain}
  Scan Started   : {start_time}
  Scan Finished  : {end_time}
  Duration       : {duration}s
  Rounds (graph) : {rounds}
  Subdomains     : {total_found} found / {total_alive} resolved / {total_services} with services
  Wildcard DNS   : {wildcard_status}
  Sources Used   : {sources}

══════════════════════════════════════════════════════════════════════════════
  DETAILED RECORDS
══════════════════════════════════════════════════════════════════════════════
{blocks}
══════════════════════════════════════════════════════════════════════════════
  END OF REPORT
══════════════════════════════════════════════════════════════════════════════
"""

HOST_BLOCK = """  ┌─ {hostname}
  │  IPv4        : {ips}
  │  IPv6        : {ipv6}
  │  PTR         : {ptr}
  │  CNAME       : {cname}
  │  HTTP        : {http_status}{redir}
  │  Ports       : {ports}
  │  Technology  : {tech}
  │  WAF / CDN   : {waf} / {cdn}
  │  Sec-headers : missing {missing_sec}
  │  TLS issuer  : {tls_issuer}  (exp {tls_exp})
  │  DNS records : {dns_records}
  │  ASN / Geo   : {asn} / {geo}
  │  JS intel    : {js_intel}
  │  CVEs        : {cves}
  └─────────────────────────────────────────────────────────────────────────
"""


def format_txt_report(domain, results, start_dt, end_dt, sources,
                      scan_ports_flag, wildcard_ips, rounds):
    duration = round((end_dt - start_dt).total_seconds(), 1)
    blocks = []
    for r in sorted(results, key=lambda x: x["hostname"]):
        ii = r.get("ip_info", {}); tls = r.get("tls", {}); dr = r.get("dns_records", {})
        ji = r.get("js_intel", {})
        js_summary = ", ".join(
            f"{k}:{len(ji.get(k, []))}" for k in ("hosts", "apis", "ws", "cloud")
            if ji.get(k)) or "—"
        redir = f"  → {r['redirected_to']}" if r.get("redirected_to") and \
            r["redirected_to"].rstrip("/") not in (f"https://{r['hostname']}",
                                                    f"http://{r['hostname']}") else ""
        blocks.append(HOST_BLOCK.format(
            hostname=r["hostname"],
            ips=", ".join(r.get("ips", [])) or "—",
            ipv6=", ".join(r.get("ipv6", [])) or "—",
            ptr=", ".join(r.get("ptr", [])) or "—",
            cname=r.get("cname") or "—",
            http_status=r.get("http_status") or "—", redir=redir,
            ports=(", ".join(f"{p}/{n}" for p, n in sorted(r["open_ports"].items()))
                   if r.get("open_ports") else ("not scanned" if not scan_ports_flag else "—")),
            tech=_tech_string(r),
            waf=(f"{r['waf']} ({r.get('waf_confidence',0)}%)" if r.get("waf") else "—"),
            cdn=r.get("cdn") or "—",
            missing_sec=", ".join(r.get("missing_sec", [])) or "none",
            tls_issuer=tls.get("issuer") or "—", tls_exp=tls.get("not_after") or "—",
            dns_records=(f"MX:{len(dr.get('mx',[]))} NS:{len(dr.get('ns',[]))} "
                         f"TXT:{len(dr.get('txt',[]))} DNSSEC:{'yes' if dr.get('dnssec') else 'no'}"
                         if dr else "—"),
            asn=ii.get("asn_org") or "—",
            geo=", ".join(filter(None, [ii.get("country"), ii.get("city")])) or "—",
            js_intel=js_summary,
            cves=", ".join(r.get("shodan", {}).get("vulns", [])) or "—",
        ))
    wc = (f"DETECTED — {', '.join(wildcard_ips)}" if wildcard_ips else "Not detected")
    return TXT_TEMPLATE.format(
        domain=domain, start_time=start_dt.strftime("%Y-%m-%d %H:%M:%S"),
        end_time=end_dt.strftime("%Y-%m-%d %H:%M:%S"), duration=duration, rounds=rounds,
        total_found=len(results),
        total_alive=sum(1 for r in results if r.get("ips") or r.get("ipv6")),
        total_services=sum(1 for r in results if r.get("services")),
        wildcard_status=wc, sources=", ".join(sources), blocks="".join(blocks))


def format_html_report(domain, results, start_dt, end_dt, sources,
                       scan_ports_flag, wildcard_ips, rounds):
    duration    = round((end_dt - start_dt).total_seconds(), 1)
    total_alive = sum(1 for r in results if r["ips"] or r["ipv6"])
    total_svc   = sum(1 for r in results if r["services"])
    total_wafs  = sum(1 for r in results if r.get("waf"))
    total_cves  = sum(len(r.get("shodan", {}).get("vulns", [])) for r in results)

    rows = []
    for r in sorted(results, key=lambda x: x["hostname"]):
        scores = r.get("service_scores", {})
        host = r["hostname"]; ips = ", ".join(r["ips"]) or "—"
        http_st = r.get("http_status"); services = r["services"]
        waf = r.get("waf") or "—"; waf_conf = r.get("waf_confidence", 0)
        cdn = r.get("cdn") or "—"
        versions = ", ".join(r.get("versions", [])) or "—"
        title = (r.get("title") or "").replace("<", "&lt;").replace(">", "&gt;")
        ii = r.get("ip_info", {})
        geo = ", ".join(filter(None, [ii.get("country"), ii.get("city")])) or "—"
        cves = ", ".join(r.get("shodan", {}).get("vulns", [])) or "—"
        miss = len(r.get("missing_sec", []))
        ji = r.get("js_intel", {})
        js_n = sum(len(ji.get(k, [])) for k in ("hosts", "apis", "ws", "cloud"))
        ports_str = (", ".join(f"{p}/{n}" for p, n in sorted(r["open_ports"].items()))
                     if r.get("open_ports") and scan_ports_flag else "—")

        st_class = ""
        if http_st:
            if 200 <= http_st < 300: st_class = "bg"
            elif 300 <= http_st < 400: st_class = "bb"
            elif http_st in (401, 403): st_class = "bo"
            else: st_class = "br"
        http_badge = (f'<span class="badge {st_class}">{http_st}</span>'
                      if st_class else (str(http_st) if http_st else "—"))
        svc_html = " ".join(
            f'<span class="svc-item" title="{scores.get(s,0)}% confidence">{s}'
            f'<span class="conf-bar"><span style="width:{scores.get(s,0)}%"></span></span></span>'
            for s in services) or "—"
        waf_html = (f'<span class="badge bp">{waf} {waf_conf}%</span>' if waf != "—" else "—")
        cve_html = (f'<span class="badge br">{cves}</span>' if cves != "—" else "—")
        sec_html = (f'<span class="badge bo">{miss} missing</span>' if miss else
                    '<span class="badge bg">ok</span>')

        rows.append(f"""
        <tr data-svc="{' '.join(services)}" data-waf="{waf}" data-cve="{cves}">
          <td class="hcell"><a href="https://{host}" target="_blank" rel="noopener">{host}</a></td>
          <td class="mono">{ips}</td>
          <td data-n="{http_st or 0}">{http_badge}</td>
          <td class="scell">{svc_html}</td>
          <td>{waf_html}</td>
          <td>{cdn}</td>
          <td>{sec_html}</td>
          <td data-n="{js_n}">{js_n}</td>
          <td>{cve_html}</td>
          <td class="vmono">{versions}</td>
          <td>{geo}</td>
          <td class="mono">{ports_str}</td>
          <td class="tcell" title="{title}">{title[:60] + "…" if len(title) > 60 else title}</td>
        </tr>""")

    all_services = sorted({s for r in results for s in r["services"]})
    svc_opts = "\n".join(f'<option value="{s}">{s}</option>' for s in all_services)
    all_wafs = sorted({r["waf"] for r in results if r.get("waf")})
    waf_opts = "\n".join(f'<option value="{w}">{w}</option>' for w in all_wafs)
    wc_html = (f'<span style="color:var(--rd)">⚠ Wildcard: {", ".join(wildcard_ips)}</span>'
               if wildcard_ips else '<span style="color:var(--gn)">✓ No wildcard</span>')

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SubRecon v4 — {domain}</title>
<style>
:root{{--bg:#0d1117;--card:#161b22;--brd:#30363d;--tx:#e6edf3;--mu:#8b949e;
--ac:#58a6ff;--gn:#3fb950;--rd:#f85149;--or:#d29922;--bl:#58a6ff;--pu:#bc8cff;
--fn:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;}}
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
.ctrl input{{width:220px}}.ctrl label{{color:var(--mu);font-size:.82em}}
.btn{{background:var(--ac);color:#0d1117;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-weight:600}}
.rc{{color:var(--mu);font-size:.82em;margin-left:auto}}
.tw{{overflow-x:auto;padding:0 28px 28px}}
table{{width:100%;border-collapse:collapse;margin-top:14px}}
th{{background:var(--card);color:var(--mu);text-align:left;padding:9px 10px;font-size:.72em;text-transform:uppercase;border-bottom:2px solid var(--brd);cursor:pointer;user-select:none;white-space:nowrap}}
th:hover{{color:var(--tx)}}
td{{padding:9px 10px;border-bottom:1px solid var(--brd);vertical-align:top}}
tr:hover td{{background:rgba(88,166,255,.04)}}tr.hidden{{display:none}}
.hcell a{{color:var(--ac);text-decoration:none;font-weight:500}}
.scell{{max-width:230px}}.tcell{{color:var(--mu);font-size:.82em;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.mono{{font-family:monospace;font-size:.85em}}.vmono{{font-family:monospace;font-size:.8em;color:var(--mu)}}
.badge{{display:inline-block;padding:2px 7px;border-radius:10px;font-size:.72em;font-weight:600}}
.bg{{background:rgba(63,185,80,.15);color:var(--gn)}}.br{{background:rgba(248,81,73,.15);color:var(--rd)}}
.bo{{background:rgba(210,153,34,.15);color:var(--or)}}.bb{{background:rgba(88,166,255,.15);color:var(--bl)}}
.bp{{background:rgba(188,140,255,.15);color:var(--pu)}}
.svc-item{{display:inline-block;margin:1px 3px 3px 0;white-space:nowrap;font-size:.8em}}
.conf-bar{{display:inline-block;width:30px;height:4px;background:var(--brd);border-radius:2px;margin-left:4px;vertical-align:middle}}
.conf-bar span{{display:block;height:100%;background:var(--ac);border-radius:2px}}
.nores{{text-align:center;color:var(--mu);padding:36px}}
footer{{text-align:center;color:var(--mu);font-size:.78em;padding:18px;border-top:1px solid var(--brd)}}
</style></head><body>
<div class="hdr"><h1>🔍 SubRecon v4 — {domain}</h1>
<div class="meta"><span>🕐 {start_dt.strftime("%Y-%m-%d %H:%M:%S")}</span>
<span>⏱ {duration}s</span><span>🔁 {rounds} rounds</span>
<span>📡 {", ".join(sources)}</span><span>{wc_html}</span></div></div>
<div class="stats">
<div class="sc"><div class="n">{len(results)}</div><div class="l">Subdomains</div></div>
<div class="sc"><div class="n" style="color:var(--gn)">{total_alive}</div><div class="l">Resolved</div></div>
<div class="sc"><div class="n" style="color:var(--bl)">{total_svc}</div><div class="l">With Services</div></div>
<div class="sc"><div class="n" style="color:var(--pu)">{total_wafs}</div><div class="l">WAF</div></div>
<div class="sc"><div class="n" style="color:var(--rd)">{total_cves}</div><div class="l">CVEs</div></div>
</div>
<div class="ctrl"><label>Filter:</label>
<input id="si" type="text" placeholder="hostname, IP, tech…" oninput="af()">
<select id="sf" onchange="af()"><option value="">All services</option>{svc_opts}</select>
<select id="wf" onchange="af()"><option value="">All WAF</option>{waf_opts}</select>
<button class="btn" onclick="rf()">Reset</button><span class="rc" id="rc"></span></div>
<div class="tw"><table id="mt"><thead><tr>
<th onclick="st(0)">Hostname</th><th onclick="st(1)">IPs</th><th onclick="st(2)">Status</th>
<th onclick="st(3)">Services</th><th onclick="st(4)">WAF</th><th onclick="st(5)">CDN</th>
<th onclick="st(6)">Sec-hdr</th><th onclick="st(7)">JS</th><th onclick="st(8)">CVEs</th>
<th onclick="st(9)">Versions</th><th onclick="st(10)">Geo</th><th onclick="st(11)">Ports</th>
<th onclick="st(12)">Title</th></tr></thead>
<tbody id="tb">{"".join(rows)}</tbody></table>
<div class="nores" id="nr" style="display:none">No results match the filters.</div></div>
<footer>Generated by SubRecon v4 · {end_dt.strftime("%Y-%m-%d %H:%M:%S")}</footer>
<script>
let sc=-1,sa=true;
function af(){{
 const q=document.getElementById('si').value.toLowerCase();
 const sf=document.getElementById('sf').value.toLowerCase();
 const wf=document.getElementById('wf').value.toLowerCase();
 const rows=document.querySelectorAll('#tb tr');let v=0;
 rows.forEach(r=>{{
  const txt=r.textContent.toLowerCase();
  const sv=(r.dataset.svc||'').toLowerCase();
  const wv=(r.dataset.waf||'').toLowerCase();
  let ok=true;
  if(q&&!txt.includes(q))ok=false;
  if(sf&&!sv.includes(sf))ok=false;
  if(wf&&!wv.includes(wf))ok=false;
  r.classList.toggle('hidden',!ok);if(ok)v++;
 }});
 document.getElementById('rc').textContent=v+' / '+rows.length;
 document.getElementById('nr').style.display=v===0?'block':'none';
}}
function rf(){{['si','sf','wf'].forEach(id=>document.getElementById(id).value='');af();}}
function st(col){{
 const tb=document.getElementById('tb');
 const rows=Array.from(tb.querySelectorAll('tr'));
 if(sc===col)sa=!sa;else{{sc=col;sa=true;}}
 rows.sort((a,b)=>{{
  const ca=a.cells[col],cb=b.cells[col];
  const na=ca.dataset.n,nb=cb.dataset.n;
  let av,bv;
  if(na!==undefined&&nb!==undefined){{av=parseFloat(na);bv=parseFloat(nb);
   return sa?av-bv:bv-av;}}
  av=(ca.textContent||'').trim();bv=(cb.textContent||'').trim();
  return sa?av.localeCompare(bv):bv.localeCompare(av);
 }});
 rows.forEach(r=>tb.appendChild(r));af();
}}
window.addEventListener('load',()=>{{const r=document.querySelectorAll('#tb tr');
 document.getElementById('rc').textContent=r.length+' / '+r.length;}});
</script></body></html>"""


# ═══════════════════════════════════════════════════════════════════════════════
#  SCOPE  +  RESUME
# ═══════════════════════════════════════════════════════════════════════════════

def load_scope(domain, scope_file) -> Set[str]:
    scope = {domain}
    if scope_file and Path(scope_file).exists():
        for line in Path(scope_file).read_text().splitlines():
            line = line.strip().lower().lstrip("*.")
            if line and not line.startswith("#"):
                scope.add(line)
    return scope


def in_scope(host, scope: Set[str]) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in scope)


def state_path(base): return base + ".state.json"

def load_state(base):
    p = Path(state_path(base))
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {"seen": [], "results": []}

def save_state(base, seen, results):
    try:
        Path(state_path(base)).write_text(json.dumps(
            {"seen": sorted(seen),
             "results": [r["hostname"] for r in results]}, ensure_ascii=False))
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="SubRecon v4 — subdomain enum, graph recon & fingerprinting",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("-w", "--wordlist")
    p.add_argument("-o", "--output")
    p.add_argument("-t", "--threads", type=int, default=25)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--depth", type=int, default=1, help="Graph expansion depth (default:1)")
    p.add_argument("--ports", action="store_true")
    p.add_argument("--js", action="store_true", help="Enable JS recon (endpoint/host extraction)")
    p.add_argument("--dns-records", action="store_true", help="Fetch MX/NS/TXT/SOA/DNSSEC")
    p.add_argument("--reverse-ip", action="store_true", help="Passive reverse-IP (report-only)")
    p.add_argument("--no-bruteforce", action="store_true")
    p.add_argument("--no-recursive", action="store_true")
    p.add_argument("--no-passive", action="store_true")
    p.add_argument("--no-osint", action="store_true")
    p.add_argument("--no-wildcard-check", action="store_true")
    p.add_argument("--min-confidence", type=int, default=DEFAULT_MIN_CONFIDENCE)
    p.add_argument("--scope-file", help="Extra in-scope domains for graph expansion")
    p.add_argument("--proxy", help="http(s)://.. or socks5://.. for all HTTP")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--virustotal", metavar="KEY")
    p.add_argument("--securitytrails", metavar="KEY")
    p.add_argument("--shodan", metavar="KEY")
    p.add_argument("--chaos", metavar="KEY")
    p.add_argument("--censys-id", metavar="ID")
    p.add_argument("--censys-secret", metavar="SECRET")
    p.add_argument("--github-token", metavar="TOKEN")
    return p.parse_args()


def configure_rate_limits(rl: AsyncRateLimiter):
    # conservative defaults; tune per your plan
    rl.configure("ip-api", per_minute=40)
    rl.configure("virustotal", per_minute=4)          # VT free tier
    rl.configure("securitytrails", per_minute=30)
    rl.configure("shodan", per_minute=60, burst=2)
    rl.configure("chaos", per_minute=60, burst=3)
    rl.configure("censys", per_minute=60, burst=2)
    rl.configure("github", per_minute=25)             # code search secondary limits
    rl.configure("crtsh", per_minute=30)
    rl.configure("hackertarget", per_minute=20)
    rl.configure("rapiddns", per_minute=20)
    rl.configure("urlscan", per_minute=30)
    rl.configure("certspotter", per_minute=30)
    rl.configure("anubis", per_minute=30)
    rl.configure("webarchive", per_minute=20)
    rl.configure("alienvault", per_minute=30)


def setup_proxy(proxy_url):
    global _PROXY
    if not proxy_url:
        return
    if proxy_url.startswith(("socks4", "socks5")):
        if not HAS_AIOHTTP_SOCKS:
            cprint(C.YLW, "  [!] SOCKS proxy requested but aiohttp_socks missing "
                          "(pip install aiohttp_socks) — proxy disabled for async HTTP")
            _PROXY = (None, None)
        else:
            _PROXY = (proxy_url, None)   # connector-level
    else:
        _PROXY = (None, proxy_url)       # per-request for http(s)


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    global _POOL, _RL
    args = parse_args()
    domain = args.domain.lower().strip().rstrip(".")

    cprint(C.MAG, BANNER)
    cprint(C.BOLD, f"  Target : {domain}")
    cprint(C.GRY, f"  Engine : aiohttp={'yes' if HAS_AIOHTTP else 'NO'} | "
                  f"dnspython={'yes' if HAS_DNSPYTHON else 'NO'} | "
                  f"socks={'yes' if HAS_AIOHTTP_SOCKS else 'no'}")
    print()

    setup_proxy(args.proxy)
    _RL = AsyncRateLimiter()
    configure_rate_limits(_RL)

    # Resolver pool
    _POOL = ResolverPool()
    cprint(C.CYN, "  [*] Benchmarking resolvers…")
    healthy = _POOL.benchmark()
    if healthy:
        fastest = ", ".join(f"{ns}({int(l*1000)}ms)" for ns, l in healthy[:5])
        cprint(C.GRN, f"  [✓] Fastest resolvers: {fastest}")
    else:
        cprint(C.YLW, "  [!] No public resolver reachable — using system DNS")
    print()

    scope = load_scope(domain, args.scope_file)
    keys = {"vt": args.virustotal or "", "st": args.securitytrails or "",
            "shodan": args.shodan or "", "chaos": args.chaos or "",
            "censys_id": args.censys_id or "", "censys_secret": args.censys_secret or "",
            "github": args.github_token or ""}

    start_dt = datetime.datetime.now()
    base = (args.output or f"{domain}_recon_{start_dt.strftime('%Y%m%d_%H%M%S')}"
            ).replace(".txt", "").replace(".html", "")

    seen: Set[str] = set()
    results: List[dict] = []
    sources_used: List[str] = []

    if args.resume:
        st = load_state(base)
        seen |= set(st.get("seen", []))
        if seen:
            cprint(C.GRY, f"  [*] Resume: {len(seen)} hosts already seen")

    # ── Wildcard ──────────────────────────────────────────────────────────────
    wildcard_ips = None
    if not args.no_wildcard_check:
        cprint(C.CYN, "  [*] Checking for wildcard DNS…")
        wildcard_ips = detect_wildcard(domain)
        cprint(C.YLW if wildcard_ips else C.GRN,
               f"  [{'!' if wildcard_ips else '✓'}] "
               + (f"Wildcard: {', '.join(wildcard_ips)}" if wildcard_ips
                  else "No wildcard"))
        print()

    # ── Round 0 candidates: passive + TLS SAN + bruteforce ────────────────────
    candidates: Set[str] = {domain}

    if not args.no_passive:
        cprint(C.CYN, "  [*] Passive sources (concurrent)…")
        src_results = asyncio.run(fetch_passive_sources_async(domain, keys)) \
            if HAS_AIOHTTP else {}
        if not HAS_AIOHTTP:
            cprint(C.YLW, "  [!] aiohttp missing — passive sources skipped")
        for src, found in src_results.items():
            found = {h for h in found if in_scope(h, scope)}
            candidates |= found
            sources_used.append(src)
            status(src, f"{len(found)} subdomains", C.GRN)

    cprint(C.GRY, "  [*] TLS SANs from apex…")
    sans = {s for s in get_tls_info(domain).get("sans", set()) if in_scope(s, scope)}
    if sans:
        candidates |= sans
        sources_used.append("TLS-SAN")
        status("TLS SANs", f"{len(sans)} subdomains", C.GRN)

    if not args.no_bruteforce:
        wordlist = DEFAULT_WORDLIST
        if args.wordlist and Path(args.wordlist).exists():
            wordlist = [l.strip() for l in Path(args.wordlist).read_text().splitlines()
                        if l.strip() and not l.startswith("#")]
            cprint(C.GRN, f"  [*] Custom wordlist: {len(wordlist)} words")
        sources_used.append("DNS-bruteforce")
        candidates |= bruteforce_subdomains(domain, wordlist, args.threads,
                                            wildcard_ips, not args.no_recursive)

    # ── Graph rounds ──────────────────────────────────────────────────────────
    rounds = 0
    to_process = {h for h in candidates if in_scope(h, scope) and h not in seen}

    while to_process and rounds <= args.depth:
        rounds += 1
        batch = sorted(to_process)
        seen |= to_process
        cprint(C.CYN, f"\n  [*] Round {rounds}: resolving {len(batch)} hosts…")

        # DNS + ports + records + TLS (threaded)
        def dns_task(h):
            r = recon_dns_only(h, args.ports, args.timeout, args.dns_records)
            tag = "+" if (r["ips"] or r["ipv6"]) else "-"
            status(tag, f"{h:<45} {', '.join(r['ips']) or 'unresolved'}",
                   C.GRN if tag == "+" else C.GRY)
            return r

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            round_results = list(ex.map(dns_task, batch))
        resolved = [r for r in round_results if r["ips"] or r["ipv6"]]
        cprint(C.GRN, f"  [+] Resolved {len(resolved)}/{len(batch)}")

        # HTTP fingerprint + JS + enrich (async)
        if resolved:
            cprint(C.CYN, f"  [*] Fingerprinting {len(resolved)} hosts"
                          f"{' + JS recon' if args.js else ''}…")
            fp_map = asyncio.run(process_hosts_async(
                resolved, args.min_confidence, domain, args.js,
                args.shodan or "", args.no_osint)) if HAS_AIOHTTP else {}
            apply_fp_results(resolved, fp_map)

        results.extend(round_results)

        # Discover new in-scope candidates from SANs + JS + reverse-IP
        new_hosts: Set[str] = set()
        for r in resolved:
            for s in r.get("tls", {}).get("sans", []):
                if in_scope(s, scope):
                    new_hosts.add(s)
            for h in r.get("js_intel", {}).get("hosts", []):
                if in_scope(h, scope):
                    new_hosts.add(h)
            if args.reverse_ip and r.get("ips"):
                for co in reverse_ip_lookup(r["ips"][0]):
                    if in_scope(co, scope):
                        new_hosts.add(co)

        new_hosts -= seen
        if new_hosts and rounds <= args.depth:
            cprint(C.MAG, f"  [→] Graph expansion: {len(new_hosts)} new in-scope hosts")
            if "Graph-expansion" not in sources_used:
                sources_used.append("Graph-expansion")
        to_process = new_hosts

        save_state(base, seen, results)

    # ── Reports ───────────────────────────────────────────────────────────────
    resolved_all = [r for r in results if r["ips"] or r["ipv6"]]
    end_dt = datetime.datetime.now()

    txt = format_txt_report(domain, resolved_all, start_dt, end_dt,
                            sources_used, args.ports, wildcard_ips, rounds)
    html = format_html_report(domain, resolved_all, start_dt, end_dt,
                              sources_used, args.ports, wildcard_ips, rounds)
    Path(base + ".txt").write_text(txt, encoding="utf-8")
    Path(base + ".html").write_text(html, encoding="utf-8")
    cprint(C.GRN, f"\n  [✓] TXT  → {base}.txt")
    cprint(C.GRN, f"  [✓] HTML → {base}.html")
    if args.json:
        Path(base + ".json").write_text(
            json.dumps(resolved_all, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        cprint(C.GRN, f"  [✓] JSON → {base}.json")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    cprint(C.BOLD, "  SUMMARY")
    cprint(C.GRY, "  " + "─" * 60)
    status("Rounds", str(rounds), C.CYN)
    status("Resolved", str(len(resolved_all)), C.GRN)
    status("WAFs", str(sum(1 for r in resolved_all if r.get("waf"))), C.MAG)
    status("CVEs", str(sum(len(r.get("shodan", {}).get("vulns", []))
                           for r in resolved_all)), C.RED)
    all_svcs: Dict[str, int] = {}
    for r in resolved_all:
        for s in r["services"]:
            all_svcs[s] = all_svcs.get(s, 0) + 1
    if all_svcs:
        cprint(C.CYN, "\n  Detected services (by frequency):")
        for svc, cnt in sorted(all_svcs.items(), key=lambda x: -x[1]):
            print(f"    {svc:<42} × {cnt}")
    print()


if __name__ == "__main__":
    main()
