#!/home/matt/workspace/personal/netdevops-projects/dnscheck/.venv/bin/python3
"""
dnscheck — Multi-resolver DNS comparison tool.

Resolves a domain against multiple DNS resolvers simultaneously and diffs
the results. Useful for debugging split-horizon DNS, propagation issues,
or resolver discrepancies.

Usage:
    dnscheck example.com
    dnscheck example.com --type MX --type TXT
    dnscheck example.com --resolvers 8.8.8.8 1.1.1.1 9.9.9.9
    dnscheck example.com --resolvers-file resolvers.yaml
    dnscheck example.com --json
"""

import argparse
import json
import socket
import sys
import threading
from datetime import datetime
from typing import Optional

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


DEFAULT_RESOLVERS = [
    {"name": "Google", "ip": "8.8.8.8"},
    {"name": "Google-2", "ip": "8.8.4.4"},
    {"name": "Cloudflare", "ip": "1.1.1.1"},
    {"name": "Cloudflare-2", "ip": "1.0.0.1"},
    {"name": "Quad9", "ip": "9.9.9.9"},
    {"name": "OpenDNS", "ip": "208.67.222.222"},
]

DEFAULT_RECORD_TYPES = ["A", "AAAA"]


def resolve_with_dnspython(domain: str, rtype: str, resolver_ip: str, timeout: float = 3.0) -> dict:
    """Resolve using dnspython library."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [resolver_ip]
    r.timeout = timeout
    r.lifetime = timeout + 1

    try:
        answers = r.resolve(domain, rtype)
        records = sorted([str(rdata) for rdata in answers])
        return {"records": records, "ttl": answers.rrset.ttl, "error": None}
    except dns.resolver.NXDOMAIN:
        return {"records": [], "ttl": None, "error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"records": [], "ttl": None, "error": "NOERROR (no answer)"}
    except dns.resolver.NoNameservers:
        return {"records": [], "ttl": None, "error": "no nameservers"}
    except dns.exception.Timeout:
        return {"records": [], "ttl": None, "error": "timeout"}
    except Exception as e:
        return {"records": [], "ttl": None, "error": str(e)}


def resolve_with_socket(domain: str, rtype: str, timeout: float = 3.0) -> dict:
    """Fallback resolver using socket (A records only, uses system resolver)."""
    if rtype not in ("A", "AAAA"):
        return {"records": [], "ttl": None, "error": f"socket fallback only supports A/AAAA, not {rtype}"}
    try:
        family = socket.AF_INET6 if rtype == "AAAA" else socket.AF_INET
        results = socket.getaddrinfo(domain, None, family)
        records = sorted(set(r[4][0] for r in results))
        return {"records": records, "ttl": None, "error": None}
    except socket.gaierror as e:
        return {"records": [], "ttl": None, "error": str(e)}


def query_resolver(domain: str, rtype: str, resolver: dict, timeout: float) -> dict:
    """Query a single resolver for a domain/type."""
    if HAS_DNSPYTHON:
        result = resolve_with_dnspython(domain, rtype, resolver["ip"], timeout)
    else:
        result = resolve_with_socket(domain, rtype, timeout)

    return {
        "resolver_name": resolver["name"],
        "resolver_ip": resolver["ip"],
        "domain": domain,
        "type": rtype,
        **result,
    }


def query_all(domain: str, rtypes: list[str], resolvers: list[dict], timeout: float) -> dict:
    """Query all resolvers for all record types concurrently."""
    results = {}
    lock = threading.Lock()

    def worker(rtype, resolver):
        result = query_resolver(domain, rtype, resolver, timeout)
        with lock:
            if rtype not in results:
                results[rtype] = []
            results[rtype].append(result)

    threads = []
    for rtype in rtypes:
        for resolver in resolvers:
            t = threading.Thread(target=worker, args=(rtype, resolver), daemon=True)
            threads.append(t)
            t.start()

    for t in threads:
        t.join()

    # Sort results by resolver name within each rtype
    for rtype in results:
        results[rtype].sort(key=lambda r: r["resolver_name"])

    return results


def find_discrepancies(results_by_type: dict) -> dict:
    """Find resolvers that return different answers than the majority."""
    discrepancies = {}

    for rtype, results in results_by_type.items():
        # Group by answer set
        answer_groups = {}
        for r in results:
            key = tuple(sorted(r["records"])) if r["records"] else (r.get("error", "empty"),)
            if key not in answer_groups:
                answer_groups[key] = []
            answer_groups[key].append(r["resolver_name"])

        if len(answer_groups) > 1:
            discrepancies[rtype] = answer_groups

    return discrepancies


def color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def print_results(domain: str, results_by_type: dict, discrepancies: dict, show_ttl: bool = False):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{color(f'DNS check for {domain} — {ts}', '1')}\n")

    for rtype, results in sorted(results_by_type.items()):
        has_disc = rtype in discrepancies
        header_color = "33" if has_disc else "32"
        disc_note = color(" [MISMATCH]", "31;1") if has_disc else color(" [consistent]", "32")
        print(color(f"  {rtype} records{disc_note}", header_color))

        rows = []
        for r in results:
            resolver_label = f"{r['resolver_name']} ({r['resolver_ip']})"

            if r["error"]:
                answer = color(f"  {r['error']}", "31")
                is_odd = True
            else:
                answer = ", ".join(r["records"]) if r["records"] else "(empty)"
                if has_disc:
                    key = tuple(sorted(r["records"])) if r["records"] else (r.get("error", "empty"),)
                    disc = discrepancies[rtype]
                    majority_count = max(len(v) for v in disc.values())
                    my_count = len(disc.get(key, []))
                    is_odd = my_count < majority_count
                else:
                    is_odd = False

                if is_odd:
                    answer = color(f"  {answer}", "31")
                else:
                    answer = f"  {answer}"

            ttl_str = f"  TTL={r['ttl']}s" if show_ttl and r.get("ttl") else ""
            rows.append([resolver_label, answer + ttl_str])

        if HAS_TABULATE:
            print(tabulate(rows, tablefmt="simple", colalign=("right", "left")))
        else:
            for row in rows:
                print(f"    {row[0]:30s}  {row[1]}")
        print()

    if discrepancies:
        print(color("  Discrepancies found:", "31;1"))
        for rtype, groups in discrepancies.items():
            print(f"    {rtype}:")
            for answer, resolvers in sorted(groups.items(), key=lambda x: -len(x[1])):
                ans_str = ", ".join(answer) if answer else "(empty)"
                resolver_str = ", ".join(resolvers)
                print(f"      {ans_str}")
                print(f"        \u21b3 {resolver_str}")
        print()
    else:
        print(color("  All resolvers agree.", "32"))
        print()


def load_resolvers_from_file(path: str) -> list[dict]:
    """Load resolvers from a YAML or plain-text file."""
    with open(path) as f:
        content = f.read()

    if path.endswith((".yaml", ".yml")) and HAS_YAML:
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "resolvers" in data:
            return data["resolvers"]
        elif isinstance(data, list):
            return data
    else:
        resolvers = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                resolvers.append({"name": parts[0], "ip": parts[1]})
            else:
                resolvers.append({"name": parts[0], "ip": parts[0]})
        return resolvers


def main():
    parser = argparse.ArgumentParser(
        description="Multi-resolver DNS comparison tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dnscheck example.com
  dnscheck example.com --type MX --type TXT
  dnscheck example.com --resolvers 8.8.8.8 1.1.1.1 9.9.9.9
  dnscheck example.com --resolvers-file resolvers.yaml
  dnscheck example.com --json
        """,
    )
    parser.add_argument("domain", help="Domain to query")
    parser.add_argument(
        "--type", "-t", action="append", dest="types", metavar="TYPE",
        help="Record type(s) to query (default: A AAAA). Can be repeated.",
    )
    parser.add_argument(
        "--resolvers", "-r", nargs="+", metavar="IP",
        help="Resolver IPs to use (overrides defaults)",
    )
    parser.add_argument(
        "--resolvers-file", "-f", metavar="FILE",
        help="YAML or text file of resolvers",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="Query timeout in seconds (default: 3)")
    parser.add_argument("--ttl", action="store_true", help="Show TTL values")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    parser.add_argument(
        "--exit-code", action="store_true",
        help="Exit with non-zero code if discrepancies found",
    )
    args = parser.parse_args()

    if not HAS_DNSPYTHON:
        print(
            "Warning: dnspython not installed. Install with: pip install dnspython\n"
            "Falling back to system resolver (limited functionality).\n",
            file=sys.stderr,
        )

    resolvers = DEFAULT_RESOLVERS
    if args.resolvers_file:
        try:
            resolvers = load_resolvers_from_file(args.resolvers_file)
        except Exception as e:
            print(f"Error loading resolvers file: {e}", file=sys.stderr)
            sys.exit(1)
    if args.resolvers:
        resolvers = [{"name": ip, "ip": ip} for ip in args.resolvers]

    rtypes = args.types or DEFAULT_RECORD_TYPES

    domain = args.domain.rstrip(".")

    results_by_type = query_all(domain, rtypes, resolvers, args.timeout)
    discrepancies = find_discrepancies(results_by_type)

    if args.json_output:
        output = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "results": results_by_type,
            "discrepancies": {
                rtype: {str(k): v for k, v in groups.items()}
                for rtype, groups in discrepancies.items()
            },
        }
        print(json.dumps(output, indent=2))
    else:
        print_results(domain, results_by_type, discrepancies, show_ttl=args.ttl)

    if args.exit_code and discrepancies:
        sys.exit(1)


if __name__ == "__main__":
    main()
