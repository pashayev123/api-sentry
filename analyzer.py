
"""Static security checks for OpenAPI specifications."""

from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    location: str
    message: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


METHODS = {
    "get", "post", "put", "delete",
    "patch", "options", "head", "trace"
}


def analyze_spec(spec: dict[str, Any]) -> list[Finding]:
    if not isinstance(spec, dict):
        raise ValueError("OpenAPI root must be an object")

    findings = []

    def add(rule, severity, location, message, recommendation):
        findings.append(Finding(
            rule, severity, location,
            message, recommendation
        ))

    # AS001: HTTP server URLs
    for i, server in enumerate(spec.get("servers") or []):
        if not isinstance(server, dict):
            continue

        url = server.get("url", "")
        if isinstance(url, str):
            if urlsplit(url).scheme.lower() == "http":
                add(
                    "AS001", "medium", f"/servers/{i}/url",
                    "Server URL uses HTTP instead of HTTPS.",
                    "Use HTTPS where transport encryption is required."
                )

    # AS002: No global security requirement
    global_security = spec.get("security")

    if not global_security:
        add(
            "AS002", "medium", "/security",
            "No effective global security requirement is defined.",
            "Define appropriate security requirements globally "
            "or explicitly for each operation."
        )

    # AS005: API key in URL query
    components = spec.get("components") or {}
    schemes = components.get("securitySchemes") or {}

    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue

        if (
            scheme.get("type") == "apiKey"
            and scheme.get("in") == "query"
        ):
            add(
                "AS005", "medium",
                f"/components/securitySchemes/{name}",
                "API key is configured in a query parameter.",
                "Consider using an authorization header to reduce "
                "exposure through URLs and logs."
            )

    # Check individual API operations
    paths = spec.get("paths") or {}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            if method.lower() not in METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            location = f"/paths/{path}/{method.lower()}"
            operation_security = operation.get("security", None)

            if operation_security == []:
                add(
                    "AS003", "high", location + "/security",
                    "Operation explicitly disables inherited security.",
                    "Review whether public access is intentional."
                )
            elif operation_security:
                # A non-empty operation security requirement exists.
                continue
            elif not global_security:
                add(
                    "AS004", "high", location,
                    "Operation has no effective security requirement.",
                    "Define suitable security requirements for this operation."
                )

    return sorted(
        findings,
        key=lambda f: (
            {"high": 0, "medium": 1, "low": 2}[f.severity],
            f.rule_id,
            f.location
        )
    )
