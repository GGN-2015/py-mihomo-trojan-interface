from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, unquote, urlsplit


DEFAULT_GOOGLE_RULES = [
    "DOMAIN-SUFFIX,google.com.hk,Proxy",
    "DOMAIN-SUFFIX,google.com,Proxy",
    "DOMAIN-SUFFIX,pki.goog,Proxy",
    "DOMAIN-SUFFIX,googletrustservices.com,Proxy",
    "DOMAIN-SUFFIX,googleapis.com,Proxy",
    "DOMAIN-SUFFIX,gstatic.com,Proxy",
    "DOMAIN-SUFFIX,googleusercontent.com,Proxy",
    "DOMAIN-SUFFIX,googlevideo.com,Proxy",
    "DOMAIN-SUFFIX,ggpht.com,Proxy",
    "DOMAIN-SUFFIX,ytimg.com,Proxy",
    "DOMAIN-SUFFIX,youtube.com,Proxy",
    "DOMAIN-KEYWORD,google,Proxy",
]


@dataclass(frozen=True)
class TrojanLink:
    name: str
    password: str
    host: str
    port: int
    sni: str
    network: str


@dataclass(frozen=True)
class ResolvedTrojanConfig:
    content: str
    node: TrojanLink
    resolved_ips: list[str]
    connect_ip: str
    host_aliases: list[str]


def yaml_quote(value: object) -> str:
    text = str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def yaml_bool(value: bool) -> str:
    return "true" if value else "false"


def first_query_value(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    return values[0] if values else default


def parse_trojan_link(link: str) -> TrojanLink:
    link = link.strip().strip('"').strip("'")
    parsed = urlsplit(link)

    if parsed.scheme.lower() != "trojan":
        raise ValueError("Only trojan:// links are supported.")
    if not parsed.hostname:
        raise ValueError("Trojan link is missing server hostname.")
    if not parsed.username:
        raise ValueError("Trojan link is missing password.")

    query = parse_qs(parsed.query, keep_blank_values=True)
    name = unquote(parsed.fragment) if parsed.fragment else parsed.hostname
    password = unquote(parsed.username)
    host = parsed.hostname
    port = parsed.port or 443
    sni = first_query_value(query, "sni", host)
    network = first_query_value(query, "type", "tcp").lower() or "tcp"

    return TrojanLink(
        name=name,
        password=password,
        host=host,
        port=port,
        sni=sni,
        network=network,
    )


def unique_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_direct_host(value: str) -> str:
    host = value.strip().strip('"').strip("'").rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    elif host.startswith("."):
        host = host[1:]
    if not host:
        raise ValueError("direct host must not be empty")
    return host.lower()


def _ipv4_from_getaddrinfo(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return unique_preserve_order(info[4][0] for info in infos)


def resolve_ipv4(host: str, timeout: float = 5.0, dns_server: str = "223.5.5.5") -> list[str]:
    if is_ip_address(host):
        return [host] if "." in host else []

    try:
        completed = subprocess.run(
            ["nslookup", host, dns_server],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
        )
    except (OSError, subprocess.TimeoutExpired):
        return _ipv4_from_getaddrinfo(host)

    output = completed.stdout + "\n" + completed.stderr
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)
    result = unique_preserve_order(ip for ip in ips if is_ip_address(ip) and ip != dns_server)
    return result or _ipv4_from_getaddrinfo(host)


def resolve_cname_aliases(host: str, timeout: float = 5.0, dns_server: str = "223.5.5.5") -> list[str]:
    if is_ip_address(host):
        return []

    try:
        completed = subprocess.run(
            ["nslookup", "-type=CNAME", host, dns_server],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    output = completed.stdout + "\n" + completed.stderr
    aliases: list[str] = []
    for pattern in [
        r"canonical name\s*=\s*([^\s]+)",
        r"Aliases:\s*([^\s]+)",
    ]:
        aliases.extend(match.rstrip(".") for match in re.findall(pattern, output, flags=re.IGNORECASE))
    return [alias for alias in unique_preserve_order(aliases) if alias.lower() != host.lower()]


def tcp_connects(ip: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def tls_connect_latency(ip: str, port: int, sni: str, timeout: float = 4.0) -> float | None:
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            context = ssl._create_unverified_context()
            with context.wrap_socket(raw, server_hostname=sni):
                return time.monotonic() - start
    except OSError:
        return None


def choose_connect_ip(ips: list[str], port: int, sni: str, timeout: float) -> str:
    candidates: list[tuple[float, str]] = []
    for ip in ips:
        latency = tls_connect_latency(ip, port, sni, min(timeout, 4.0))
        if latency is not None:
            candidates.append((latency, ip))
    if candidates:
        return min(candidates)[1]

    tcp_candidates: list[tuple[float, str]] = []
    for ip in ips:
        start = time.monotonic()
        if tcp_connects(ip, port, min(timeout, 3.0)):
            tcp_candidates.append((time.monotonic() - start, ip))
    if tcp_candidates:
        return min(tcp_candidates)[1]
    return ips[0] if ips else ""


def find_running_mihomo_processes() -> list[str]:
    if sys.platform.startswith("win"):
        return _find_running_mihomo_processes_windows()
    return _find_running_mihomo_processes_posix()


def _find_running_mihomo_processes_windows() -> list[str]:
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "$names = 'mihomo|clash|verge|party'; "
                "$procs = Get-CimInstance Win32_Process | "
                "Where-Object { $_.Name -match $names } | "
                "ForEach-Object { \"$($_.ProcessId):$($_.Name)\" }; "
                "$ports = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
                "Where-Object { $_.LocalPort -in 7890,9090 } | "
                "ForEach-Object { \"listen:$($_.LocalAddress):$($_.LocalPort)\" }; "
                "$procs + $ports",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="ignore",
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    return unique_preserve_order(line.strip() for line in completed.stdout.splitlines() if line.strip())


def _find_running_mihomo_processes_posix() -> list[str]:
    try:
        completed = subprocess.run(
            ["pgrep", "-fl", "mihomo|clash|verge|party"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            encoding="utf-8",
            errors="ignore",
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    current_pid = str(os.getpid())
    return unique_preserve_order(
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip() and not line.strip().startswith(current_pid + " ")
    )


def flush_windows_dns() -> bool:
    if not sys.platform.startswith("win"):
        return False

    try:
        completed = subprocess.run(
            ["ipconfig", "/flushdns"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            encoding="utf-8",
            errors="ignore",
        )
    except (OSError, subprocess.TimeoutExpired):
        return False

    return completed.returncode == 0


def build_yaml(
    node: TrojanLink,
    *,
    mixed_port: int,
    controller: str,
    log_level: str,
    enable_tun: bool,
    server_ips: list[str],
    connect_ip: str,
    skip_cert_verify: bool,
    interface_name: str,
    node_name: str,
    host_aliases: list[str],
    direct_hosts: list[str],
) -> str:
    pinned_ips = unique_preserve_order([*server_ips, connect_ip])
    server = connect_ip or (server_ips[0] if server_ips else node.host)
    route_excludes = pinned_ips if pinned_ips else ([node.host] if is_ip_address(node.host) else [])
    display_name = node_name or node.name

    host_map: dict[str, list[str]] = {}
    if pinned_ips and not is_ip_address(node.host):
        for host in unique_preserve_order([node.host, *host_aliases]):
            host_map[host] = pinned_ips

    lines: list[str] = [
        f"mixed-port: {mixed_port}",
        "allow-lan: false",
        "bind-address: 127.0.0.1",
        "mode: rule",
        f"log-level: {log_level}",
        "ipv6: false",
        f"interface-name: {yaml_quote(interface_name)}" if interface_name else 'interface-name: ""',
        "geodata-mode: false",
        "geo-auto-update: false",
        "geo-update-interval: 24",
        f"external-controller: {yaml_quote(controller)}",
        'secret: ""',
        "unified-delay: true",
        "tcp-concurrent: false",
        "",
        "tun:",
        f"  enable: {yaml_bool(enable_tun)}",
        "  stack: mixed",
        "  auto-route: true",
        "  auto-detect-interface: true",
        "  strict-route: false",
    ]

    if route_excludes:
        lines.append("  route-exclude-address:")
        for value in route_excludes:
            suffix = "/32" if "." in value and "/" not in value else ""
            lines.append(f"    - {value}{suffix}")

    lines.extend(
        [
            "  dns-hijack:",
            "    - 198.18.0.2:53",
            "    - tcp://198.18.0.2:53",
            "    - any:53",
            "    - tcp://any:53",
            "",
            "profile:",
            "  store-selected: true",
            "  store-fake-ip: false",
            "",
            "dns:",
            "  enable: true",
            "  listen: 0.0.0.0:1053",
            "  ipv6: false",
            "  respect-rules: true",
            "  enhanced-mode: redir-host",
            "  use-hosts: true",
            "  use-system-hosts: true",
            "  proxy-server-nameserver:",
            "    - 223.5.5.5",
            "    - 119.29.29.29",
            "    - https://dns.alidns.com/dns-query",
            "    - https://doh.pub/dns-query",
        ]
    )

    if host_map:
        lines.append("  nameserver-hosts:")
        for host, ips in host_map.items():
            lines.append(f"    {yaml_quote(host)}:")
            for ip in ips:
                lines.append(f"      - {ip}")

    lines.extend(
        [
            "  default-nameserver:",
            "    - 223.5.5.5",
            "    - 119.29.29.29",
            "  nameserver:",
            "    - https://dns.alidns.com/dns-query",
            "    - https://doh.pub/dns-query",
            "  fallback:",
            "    - https://1.1.1.1/dns-query",
            "    - https://8.8.8.8/dns-query",
            "  fallback-filter:",
            "    geoip: true",
            "    geoip-code: CN",
            "",
            "sniffer:",
            "  enable: true",
            "  force-dns-mapping: true",
            "  parse-pure-ip: false",
            "  sniff:",
            "    TLS:",
            "      ports:",
            "        - 443",
            "        - 8443",
            "    HTTP:",
            "      ports:",
            "        - 80",
            "        - 8080-8880",
            "      override-destination: true",
            "    QUIC:",
            "      ports:",
            "        - 443",
            "        - 8443",
            "",
            "proxies:",
            f"  - name: {yaml_quote(display_name)}",
            "    type: trojan",
            f"    server: {server}",
            f"    port: {node.port}",
            f"    password: {yaml_quote(node.password)}",
            "    udp: true",
            "    tls: true",
            f"    sni: {yaml_quote(node.sni)}",
            f"    network: {yaml_quote(node.network)}",
            f"    skip-cert-verify: {yaml_bool(skip_cert_verify)}",
            "",
            "proxy-groups:",
            '  - name: "Proxy"',
            "    type: select",
            "    proxies:",
            f"      - {yaml_quote(display_name)}",
            "      - DIRECT",
            "",
            "rules:",
        ]
    )

    if not is_ip_address(node.host):
        lines.append(f"  - DOMAIN,{node.host},DIRECT")
    for host in host_aliases:
        if not is_ip_address(host):
            lines.append(f"  - DOMAIN,{host},DIRECT")
    if node.sni and node.sni != node.host and not is_ip_address(node.sni):
        lines.append(f"  - DOMAIN,{node.sni},DIRECT")
    for ip in pinned_ips:
        lines.append(f"  - IP-CIDR,{ip}/32,DIRECT,no-resolve")

    for direct_host in unique_preserve_order(normalize_direct_host(value) for value in direct_hosts):
        if is_ip_address(direct_host):
            if "." in direct_host:
                lines.append(f"  - IP-CIDR,{direct_host}/32,DIRECT,no-resolve")
        else:
            lines.append(f"  - DOMAIN-SUFFIX,{direct_host},DIRECT")

    lines.extend(f"  - {rule}" for rule in DEFAULT_GOOGLE_RULES)
    lines.extend(
        [
            "  - DOMAIN-SUFFIX,local,DIRECT",
            "  - DOMAIN-SUFFIX,localhost,DIRECT",
            "  - IP-CIDR,127.0.0.0/8,DIRECT",
            "  - IP-CIDR,10.0.0.0/8,DIRECT",
            "  - IP-CIDR,172.16.0.0/12,DIRECT",
            "  - IP-CIDR,192.168.0.0/16,DIRECT",
            "  - IP-CIDR,224.0.0.0/4,DIRECT",
            "  - GEOIP,CN,DIRECT",
            "  - MATCH,Proxy",
        ]
    )

    return "\n".join(lines) + "\n"


def generate_config(
    link: str,
    *,
    mixed_port: int,
    controller: str,
    log_level: str,
    enable_tun: bool,
    keep_server_domain: bool,
    server_ips: list[str],
    connect_ip: str,
    resolve_timeout: float,
    resolve_dns_server: str,
    skip_cert_verify: bool,
    interface_name: str,
    node_name: str,
    host_aliases: list[str],
    direct_hosts: list[str],
) -> ResolvedTrojanConfig:
    node = parse_trojan_link(link)
    auto_host_aliases = (
        resolve_cname_aliases(node.host, resolve_timeout, resolve_dns_server) if not keep_server_domain else []
    )
    all_host_aliases = unique_preserve_order([*host_aliases, *auto_host_aliases])
    resolved_ips = unique_preserve_order(server_ips)
    if not resolved_ips and not keep_server_domain:
        resolved_ips = resolve_ipv4(node.host, resolve_timeout, resolve_dns_server)
    selected_connect_ip = connect_ip or choose_connect_ip(resolved_ips, node.port, node.sni, resolve_timeout)

    content = build_yaml(
        node,
        mixed_port=mixed_port,
        controller=controller,
        log_level=log_level,
        enable_tun=enable_tun,
        server_ips=resolved_ips,
        connect_ip=selected_connect_ip,
        skip_cert_verify=skip_cert_verify,
        interface_name=interface_name,
        node_name=node_name,
        host_aliases=all_host_aliases,
        direct_hosts=direct_hosts,
    )

    return ResolvedTrojanConfig(
        content=content,
        node=node,
        resolved_ips=resolved_ips,
        connect_ip=selected_connect_ip,
        host_aliases=all_host_aliases,
    )


def write_config(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
