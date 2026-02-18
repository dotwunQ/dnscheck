# dnscheck

Multi-resolver DNS comparison tool. Resolves a domain against multiple DNS resolvers simultaneously and diffs the results. Useful for debugging split-horizon DNS, propagation issues, or resolver discrepancies.

## Features

- Concurrent queries via threads — all resolvers queried at the same time
- Automatic discrepancy detection — highlights when resolvers disagree
- Supports all record types: A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR
- Color-coded output: green (consistent), red (mismatch)
- Custom resolver lists via CLI or YAML file
- JSON output for scripting and alerting
- Exit code option for use in CI/monitoring

## Install

```bash
pip install dnspython pyyaml tabulate
```

Or with pipx:
```bash
pipx install .
```

## Usage

```bash
# Check A and AAAA records (default)
dnscheck example.com

# Check specific record types
dnscheck example.com --type MX --type TXT

# Use custom resolvers
dnscheck example.com --resolvers 8.8.8.8 1.1.1.1 9.9.9.9

# Use resolvers from file
dnscheck example.com --resolvers-file resolvers.yaml

# JSON output
dnscheck example.com --json

# Show TTL values
dnscheck example.com --ttl

# Exit non-zero if discrepancies found (for scripts/CI)
dnscheck example.com --exit-code
```

## Output

```
DNS check for example.com — 2024-01-15 14:23:01

  A records [consistent]
  Google (8.8.8.8)         93.184.216.34
  Cloudflare (1.1.1.1)     93.184.216.34
  Quad9 (9.9.9.9)          93.184.216.34

  A records [MISMATCH]
  Google (8.8.8.8)         192.168.1.10   <- internal resolver returning LAN IP
  Cloudflare (1.1.1.1)     203.0.113.5
  Quad9 (9.9.9.9)          203.0.113.5
```

## Use Cases

**Split-horizon DNS debugging** — Add your internal resolver alongside public ones and see which records differ.

**DNS propagation** — After a DNS change, run against multiple resolvers to see if changes have propagated.

**Resolver comparison** — Verify your Cloudflare/Google/internal resolvers all agree on critical records.

## Resolvers File

```yaml
resolvers:
  - name: Public-Google
    ip: 8.8.8.8
  - name: Internal
    ip: 192.168.1.1
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--type`, `-t` | A, AAAA | Record type(s) to query |
| `--resolvers`, `-r` | 6 public resolvers | Resolver IPs |
| `--resolvers-file`, `-f` | — | YAML/text file of resolvers |
| `--timeout` | 3s | Query timeout |
| `--ttl` | off | Show TTL values |
| `--json` | off | JSON output |
| `--exit-code` | off | Exit 1 if discrepancies found |

## License

MIT
