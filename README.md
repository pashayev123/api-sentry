# API-Sentry

**A lightweight static security analyzer for OpenAPI specifications.**

API-Sentry is an open-source Python tool designed to help developers and application security teams identify potential security design issues in OpenAPI documents before APIs are deployed.

It analyzes API specifications and provides actionable findings related to transport security, authentication requirements, and API key handling.

## Features

- **Transport security checks** — identifies API server URLs that use HTTP instead of HTTPS.
- **Authentication coverage** — highlights API operations without an effective security requirement in the specification.
- **Security override detection** — flags operations that explicitly disable inherited security requirements.
- **API key handling** — identifies API key schemes configured to pass credentials through URL query parameters.
- **Multiple input formats** — supports OpenAPI documents in JSON and YAML formats.
- **Structured reporting** — generates readable terminal output or JSON reports.
- **Automated testing** — includes unit tests to help maintain code quality.

## Security Checks

| Rule ID | Severity | Description |
|---|---|---|
| AS001 | Medium | API server URL uses HTTP |
| AS002 | Medium | No effective global security requirement |
| AS003 | High | An operation explicitly disables inherited security |
| AS004 | High | An operation has no effective security requirement |
| AS005 | Medium | API key is configured in a query parameter |

Severity levels are initial triage priorities, not proof of exploitability. Findings should be reviewed in the context of the API's intended design.

## Requirements

- Python 3.10 or later
- PyYAML 6.x for YAML input
- No external service or API credentials required

JSON input can be processed using Python's standard library.

## Installation

Clone the repository:

```bash
git clone https://github.com/pashayev123/api-sentry.git
cd api-sentry
```

Create and activate a virtual environment.

**Windows PowerShell**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux and macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```


## Usage

Analyze an OpenAPI specification:

```bash
python -m api_sentry.cli examples/openapi-insecure.yaml
```

Generate JSON output:

```bash
python -m api_sentry.cli examples/openapi-insecure.yaml --format json
```

The report includes the rule identifier, severity, affected specification location, description, and recommended remediation.

## Example

Given an API specification containing:

```yaml
openapi: 3.0.3
info:
  title: Example API
  version: 1.0.0

servers:
  - url: http://api.example.test/v1

paths:
  /profile:
    get:
      responses:
        "200":
          description: Successful response
```

API-Sentry can identify the HTTP server URL and the absence of an effective authentication requirement for the operation.

The findings are intended to guide further review rather than establish that a deployed API is vulnerable.

## Running Tests

Run the unit test suite:

```bash
python -m unittest discover -s tests -v
```

The repository includes a GitHub Actions workflow for running tests on pushes and pull requests.

## Scope and Limitations

API-Sentry is a **static OpenAPI specification analyzer**, not a dynamic vulnerability scanner.

It does not:

- Send requests to API endpoints.
- Exploit vulnerabilities or attempt authentication bypasses.
- Verify runtime authentication or authorization enforcement.
- Guarantee complete coverage of all OpenAPI features.
- Replace manual security reviews or authorized penetration testing.

OpenAPI specifications describe intended API behavior and may not accurately represent the deployed implementation. All findings require contextual review.

## Intended Use

API-Sentry is intended for:

- Application security reviews
- Secure API design and development
- Authorized penetration-testing preparation
- CI/CD security quality checks
- Security education and research

Use the tool only with specifications you are authorized to analyze. Avoid publishing confidential API specifications, internal endpoints, credentials, or other sensitive information.

## Contributing

Contributions are welcome.

To contribute:

1. Fork the repository.
2. Create a feature branch.
3. Implement the change and add appropriate tests.
4. Run the test suite.
5. Submit a pull request describing the change and its security impact.

Please report suspected security issues privately to the repository maintainer rather than publishing sensitive details before they can be reviewed.

## Roadmap

- SARIF report output for code-scanning integrations
- Configurable rule severity and exclusions
- Improved support for OpenAPI references
- Additional authentication and authorization design checks
- Baseline comparison for tracking findings between versions
- Packaging for installation through PyPI

Roadmap items are proposals and should not be interpreted as implemented features.

## License

API-Sentry is distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

## Project Status

API-Sentry is an early-stage open-source project. Its rules, documentation, and test coverage are subject to ongoing development.

Contributions, bug reports, and feature requests help improve its usefulness to the application security community.
