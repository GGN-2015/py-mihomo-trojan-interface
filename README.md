# py-mihomo-trojan-interface

Generate a mihomo YAML config from a `trojan://` share URL, relaunch with
administrator privileges through `py-admin-launch`, and start mihomo with the
generated config.

## Install

```bash
python -m pip install -e .
```

## Usage

Prefer passing the Trojan URL through stdin, an environment variable, or a file
so the full URL does not stay in shell history.

```bash
printf '%s' 'trojan://<secret>@<host>:<port>?type=tcp&sni=<sni>#<name>' | \
  mihomo-trojan \
    --mihomo /path/to/mihomo \
    --country-mmdb /path/to/Country.mmdb \
    --trojan-url-stdin
```

PowerShell example:

```powershell
$env:MIHOMO_TROJAN_URL = 'trojan://<secret>@<host>:<port>?type=tcp&sni=<sni>#<name>'
mihomo-trojan `
  --mihomo C:\path\to\mihomo.exe `
  --country-mmdb C:\path\to\Country.mmdb `
  --trojan-url-env MIHOMO_TROJAN_URL
```

You can also pass the URL directly when needed:

```bash
mihomo-trojan \
  --mihomo /path/to/mihomo \
  --country-mmdb /path/to/Country.mmdb \
  --trojan-url 'trojan://<secret>@<host>:<port>?type=tcp&sni=<sni>#<name>'
```

The launcher passes the mihomo data directory with `-d` and the generated YAML
with `-f`. If `--data-dir` is not provided and the mmdb file is named
`Country.mmdb`, the file's parent directory is used as the mihomo data
directory.

On Linux and macOS, the launcher automatically marks the mihomo binary as
executable before starting it, equivalent to running `chmod +x` on the path
provided with `--mihomo`.

Useful options:

```bash
mihomo-trojan --help
mihomo-trojan --dry-run --mihomo /path/to/mihomo --country-mmdb /path/to/Country.mmdb --trojan-url-env MIHOMO_TROJAN_URL
```
