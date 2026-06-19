from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import __version__
from .config import (
    find_running_mihomo_processes,
    flush_windows_dns,
    generate_config,
    write_config,
)


def is_admin() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid is not None and geteuid() == 0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mihomo-trojan",
        description="Generate a mihomo Trojan YAML config, elevate privileges, and launch mihomo.",
    )
    parser.add_argument("trojan_url", nargs="?", help="trojan:// share URL")
    parser.add_argument("--mihomo", required=True, help="path to the mihomo executable")
    parser.add_argument("--country-mmdb", required=True, help="path to Country.mmdb")
    parser.add_argument("--trojan-url", dest="trojan_url_option", help="trojan:// share URL")
    parser.add_argument("--trojan-url-file", help="read the trojan:// share URL from a text file")
    parser.add_argument("--trojan-url-env", help="read the trojan:// share URL from an environment variable")
    parser.add_argument("--trojan-url-stdin", action="store_true", help="read the trojan:// share URL from stdin")
    parser.add_argument("--config", help="output mihomo YAML path; defaults to <data-dir>/mihomo-trojan.yaml")
    parser.add_argument("--data-dir", help="mihomo data directory passed to mihomo with -d")
    parser.add_argument("--mixed-port", type=int, default=7890, help="mihomo mixed proxy port")
    parser.add_argument("--controller", default="127.0.0.1:9090", help="external-controller address")
    parser.add_argument("--no-tun", action="store_true", help="disable TUN in generated config")
    parser.add_argument(
        "--keep-server-domain",
        action="store_true",
        help="keep the original server domain instead of resolving it to IPv4",
    )
    parser.add_argument("--server-ip", action="append", default=[], help="pin a server IPv4 address; repeatable")
    parser.add_argument("--connect-ip", default="", help="IPv4 address to use in proxies[].server")
    parser.add_argument("--resolve-timeout", type=float, default=5.0, help="DNS/connect timeout in seconds")
    parser.add_argument("--resolve-dns-server", default="223.5.5.5", help="DNS server used while generating")
    parser.add_argument("--strict-cert", action="store_true", help="set skip-cert-verify to false")
    parser.add_argument("--interface-name", default="", help="physical outbound interface name")
    parser.add_argument("--node-name", default="", help="override proxy node name")
    parser.add_argument("--host-alias", action="append", default=[], help="additional CNAME/host to pin; repeatable")
    parser.add_argument("--allow-running", action="store_true", help="continue even when another mihomo process is found")
    parser.add_argument("--no-flush-dns", action="store_true", help="skip ipconfig /flushdns on Windows")
    parser.add_argument("--mihomo-arg", action="append", default=[], help="extra argument passed to mihomo; repeatable")
    parser.add_argument("--no-wait-mihomo", action="store_true", help="start mihomo in the background")
    parser.add_argument("--dry-run", action="store_true", help="write the config but do not start mihomo")
    parser.add_argument("--no-elevate", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--delete-trojan-url-file", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def read_trojan_url(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    sources = [
        value is not None
        for value in [
            args.trojan_url,
            args.trojan_url_option,
            args.trojan_url_file,
            args.trojan_url_env,
        ]
    ]
    sources.append(args.trojan_url_stdin)
    if sum(1 for used in sources if used) != 1:
        parser.error("provide exactly one trojan URL source")

    if args.trojan_url is not None:
        link = args.trojan_url
    elif args.trojan_url_option is not None:
        link = args.trojan_url_option
    elif args.trojan_url_file is not None:
        path = Path(args.trojan_url_file)
        try:
            link = path.read_text(encoding="utf-8").strip()
        finally:
            if args.delete_trojan_url_file:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
    elif args.trojan_url_env is not None:
        link = os.environ.get(args.trojan_url_env, "").strip()
        if not link:
            parser.error(f"environment variable {args.trojan_url_env!r} is empty or missing")
    else:
        link = sys.stdin.read().strip()

    if not link:
        parser.error("trojan URL is empty")
    return link


def write_secret_temp_file(secret: str) -> Path:
    fd, name = tempfile.mkstemp(prefix="mihomo-trojan-url-", suffix=".txt")
    path = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(secret)
            handle.write("\n")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except BaseException:
        try:
            path.unlink()
        finally:
            raise
    return path


def resolve_executable(value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.exists():
        return candidate.resolve()

    resolved = shutil.which(value)
    if resolved:
        return Path(resolved).resolve()
    raise FileNotFoundError(f"mihomo executable not found: {value}")


def resolve_existing_file(value: str, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"{label} not found: {value}")
    return path.resolve()


def prepare_data_dir(country_mmdb: Path, requested_data_dir: str | None) -> Path:
    if requested_data_dir:
        data_dir = Path(requested_data_dir).expanduser().resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        target = data_dir / "Country.mmdb"
        if country_mmdb.resolve() != target.resolve():
            shutil.copy2(country_mmdb, target)
        return data_dir

    if country_mmdb.name == "Country.mmdb":
        return country_mmdb.parent.resolve()

    data_dir = Path(tempfile.gettempdir()) / "mihomo-trojan-interface"
    data_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(country_mmdb, data_dir / "Country.mmdb")
    return data_dir.resolve()


def config_path_for(args: argparse.Namespace, data_dir: Path) -> Path:
    if args.config:
        return Path(args.config).expanduser().resolve()
    return data_dir / "mihomo-trojan.yaml"


def child_argv_from_args(args: argparse.Namespace, trojan_url_file: Path) -> list[str]:
    child = [
        "--mihomo",
        str(args.mihomo),
        "--country-mmdb",
        str(args.country_mmdb),
        "--trojan-url-file",
        str(trojan_url_file),
        "--delete-trojan-url-file",
    ]

    if args.config:
        child.extend(["--config", args.config])
    if args.data_dir:
        child.extend(["--data-dir", args.data_dir])
    child.extend(["--mixed-port", str(args.mixed_port)])
    child.extend(["--controller", args.controller])
    if args.no_tun:
        child.append("--no-tun")
    if args.keep_server_domain:
        child.append("--keep-server-domain")
    for value in args.server_ip:
        child.extend(["--server-ip", value])
    if args.connect_ip:
        child.extend(["--connect-ip", args.connect_ip])
    child.extend(["--resolve-timeout", str(args.resolve_timeout)])
    child.extend(["--resolve-dns-server", args.resolve_dns_server])
    if args.strict_cert:
        child.append("--strict-cert")
    if args.interface_name:
        child.extend(["--interface-name", args.interface_name])
    if args.node_name:
        child.extend(["--node-name", args.node_name])
    for value in args.host_alias:
        child.extend(["--host-alias", value])
    if args.allow_running:
        child.append("--allow-running")
    if args.no_flush_dns:
        child.append("--no-flush-dns")
    for value in args.mihomo_arg:
        child.extend(["--mihomo-arg", value])
    if args.no_wait_mihomo:
        child.append("--no-wait-mihomo")
    if args.dry_run:
        child.append("--dry-run")
    return child


def relaunch_as_admin(args: argparse.Namespace, trojan_url: str) -> int:
    from py_admin_launch import launch

    args.mihomo = str(resolve_executable(args.mihomo))
    args.country_mmdb = str(resolve_existing_file(args.country_mmdb, "Country.mmdb"))
    secret_path = write_secret_temp_file(trojan_url)
    command = [
        sys.executable,
        "-m",
        "mihomo_trojan_interface",
        *child_argv_from_args(args, secret_path),
        "--no-elevate",
    ]
    try:
        result = launch(command, cwd=os.getcwd(), wait=True)
    except BaseException:
        try:
            secret_path.unlink()
        except OSError:
            pass
        raise
    return 0 if result.returncode is None else int(result.returncode)


def run_mihomo(command: list[str], cwd: Path, no_wait: bool) -> int:
    if no_wait:
        process = subprocess.Popen(command, cwd=str(cwd))
        print(f"Started mihomo with PID {process.pid}.")
        return 0
    return subprocess.run(command, cwd=str(cwd), check=False).returncode


def run(args: argparse.Namespace, trojan_url: str) -> int:
    mihomo = resolve_executable(args.mihomo)
    country_mmdb = resolve_existing_file(args.country_mmdb, "Country.mmdb")

    if not args.allow_running:
        running = find_running_mihomo_processes()
        if running:
            print("mihomo appears to be running; refusing to generate a competing config.", file=sys.stderr)
            print("Use --allow-running to override this check.", file=sys.stderr)
            return 2

    if not args.no_flush_dns:
        if flush_windows_dns():
            print("Flushed Windows DNS cache.")
        elif sys.platform.startswith("win"):
            print("Warning: failed to flush Windows DNS cache.", file=sys.stderr)

    data_dir = prepare_data_dir(country_mmdb, args.data_dir)
    config_path = config_path_for(args, data_dir)
    generated = generate_config(
        trojan_url,
        mixed_port=args.mixed_port,
        controller=args.controller,
        enable_tun=not args.no_tun,
        keep_server_domain=args.keep_server_domain,
        server_ips=args.server_ip,
        connect_ip=args.connect_ip,
        resolve_timeout=args.resolve_timeout,
        resolve_dns_server=args.resolve_dns_server,
        skip_cert_verify=not args.strict_cert,
        interface_name=args.interface_name,
        node_name=args.node_name,
        host_aliases=args.host_alias,
    )
    write_config(config_path, generated.content)

    print(f"Wrote mihomo config: {config_path}")
    print(f"Using mihomo data dir: {data_dir}")
    if args.dry_run:
        print("Dry run complete; mihomo was not started.")
        return 0

    command = [str(mihomo), "-d", str(data_dir), "-f", str(config_path), *args.mihomo_arg]
    print("Starting mihomo with administrator privileges.")
    return run_mihomo(command, data_dir, args.no_wait_mihomo)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        trojan_url = read_trojan_url(args, parser)
        if not args.no_elevate and not is_admin():
            return relaunch_as_admin(args, trojan_url)
        return run(args, trojan_url)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
