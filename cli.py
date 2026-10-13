
import argparse
import json
import sys

from .analyzer import analyze_spec
from .loader import load_spec


def main():
    parser = argparse.ArgumentParser(
        description="Static OpenAPI security analyzer"
    )
    parser.add_argument("spec", help="OpenAPI JSON or YAML file")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text"
    )
    args = parser.parse_args()

    try:
        spec = load_spec(args.spec)
        findings = analyze_spec(spec)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(
            [finding.to_dict() for finding in findings],
            indent=2
        ))
    else:
        print(f"API-Sentry: {len(findings)} finding(s)")
        for finding in findings:
            print(
                f"\n[{finding.severity.upper()}] "
                f"{finding.rule_id} {finding.location}"
            )
            print(f"  {finding.message}")
            print(f"  Recommendation: {finding.recommendation}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
