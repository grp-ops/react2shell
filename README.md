# React2Shell

CLI tool + Nuclei templates for detecting CVE-2025-55182 and CVE-2025-66478 in Next.js applications using React Server Components.

## Vulnerability Information

| CVE            | Description                                      | CVSS |
| -------------- | ------------------------------------------------ | ---- |
| CVE-2025-55182 | React Server Components insecure deserialization | 10.0 |
| CVE-2025-66478 | Next.js Server Actions RCE (duplicate)           | 10.0 |

**Affected Versions:**

- React: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Next.js: 14.3.0-canary.77 through 16.0.6

**Patched Versions:**

- React: 19.0.1, 19.1.2, 19.2.1
- Next.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7

### Detection Modes

| Mode             | Flag                 | Description                                                     |
| ---------------- | -------------------- | --------------------------------------------------------------- |
| RCE PoC          | (default)            | Executes deterministic math operation, checks header for result |
| Safe Check       | `--safe-check`       | Side-channel detection via 500 status + error digest pattern    |
| Fingerprint Only | `--fingerprint-only` | Version detection without exploit attempt                       |
| Callback         | `--callback-url URL` | Blind RCE confirmation via DNS/HTTP callback                    |

### Version Fingerprinting

Fingerprint Next.js applications before attempting exploits:

- Detect Next.js version from `x-powered-by` header
- Identifies App Router and Server Actions usage
- Skips exploit check if version is known to be patched
- Disable with `--no-fingerprint`

### WAF Bypass

`--waf-bypass` prepends random junk data to the multipart request body. This can help evade WAF content inspection that only analyzes the first portion of request bodies. Default size is 128KB, configurable via `--waf-bypass-size`. When WAF bypass enabled, timeout automatically increased to 20 seconds.

### Payload Variants

Three payload variants are available for evasion tests:

- Variant 1 (default): Original payload structure
- Variant 2: Uses `global.process` path
- Variant 3: String concatenation obfuscation

Use `--payload-variant 2` or `--payload-variant 3` to test alternative payloads.

Fingerprint only (no exploit attempt):

```bash
python3 scanner.py -u https://example.com --fingerprint-only
```

### Callback-Based Detection

For blind RCE confirmation w/ Burp Collaborator:

```bash
python3 scanner.py -u https://example.com --callback-url https://your-collaborator.burpcollaborator.net/r2s
```

### Options

Scan with custom headers:

```bash
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Windows targets:

```bash
python3 scanner.py -u https://example.com --windows
```

WAF bypass:

```bash
python3 scanner.py -u https://example.com --waf-bypass --waf-bypass-size 256
```

Use alternative payload variant:

```bash
python3 scanner.py -u https://example.com --payload-variant 2
```

Skip fingerprinting for faster scanning:

```bash
python3 scanner.py -l hosts.txt --no-fingerprint -t 50
```

## Options

```
Input:
  -u, --url             Single URL to check
  -l, --list            File containing hosts (one per line)

Detection:
  --safe-check          Use safe side-channel detection instead of RCE PoC
  --fingerprint-only    Only perform version fingerprinting, no exploit check
  --no-fingerprint      Skip version fingerprinting before exploit check
  --callback-url URL    URL for callback-based blind RCE confirmation

Payload:
  --windows             Use Windows PowerShell payload instead of Unix shell
  --payload-variant N   Payload variant for evasion (1-3, default: 1)
  --waf-bypass          Add junk data to bypass WAF content inspection
  --waf-bypass-size KB  Size of junk data in KB (default: 128)

Network:
  -t, --threads         Number of concurrent threads (default: 10)
  --timeout             Request timeout in seconds (default: 10)
  --retries             Number of retry attempts on failures (default: 2)
  --retry-delay         Delay between retries in seconds (default: 1.0)
  -k, --insecure        Disable SSL certificate verification
  -H, --header          Custom header (can be used multiple times)

Output:
  -o, --output          Output file for results (JSON)
  --all-results         Save all results, not just vulnerable hosts
  -v, --verbose         Show response details for vulnerable hosts
  -q, --quiet           Only output vulnerable hosts
  --no-color            Disable colored output
```

## Output Format

JSON output includes metadata:

```json
{
  "scan_time": "2025-12-05T12:00:00.000000Z",
  "scanner_version": "2.0.0",
  "cve_ids": ["CVE-2025-55182", "CVE-2025-66478"],
  "total_results": 100,
  "vulnerable_count": 3,
  "results": [
    {
      "host": "https://example.com",
      "vulnerable": true,
      "status_code": 200,
      "final_url": "https://example.com/",
      "detection_method": "rce_poc",
      "response_time_ms": 234.5,
      "cve_ids": ["CVE-2025-55182", "CVE-2025-66478"],
      "cvss_score": 10.0,
      "version_info": {
        "nextjs_version": "15.2.0",
        "has_app_router": true,
        "has_server_actions": true,
        "potentially_vulnerable": true
      },
      "request": "...",
      "response": "..."
    }
  ]
}
```

## Nuclei Templates

Nuclei templates are provided in the `nuclei/` directory for integration with the [Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scanner.

### Available Templates

| Template                      | Description                                     |
| ----------------------------- | ----------------------------------------------- |
| `CVE-2025-55182.yaml`         | Primary RCE detection via header reflection     |
| `CVE-2025-55182-safe.yaml`    | Safe side-channel detection (no code execution) |
| `CVE-2025-55182-oob.yaml`     | Out-of-band callback confirmation               |
| `CVE-2025-55182-windows.yaml` | Windows-specific PowerShell payload             |
| `nextjs-version-detect.yaml`  | Next.js fingerprinting and version detection    |
| `react2shell-workflow.yaml`   | Chained workflow for comprehensive detection    |

### Usage

Single target:

```bash
nuclei -u https://example.com -t nuclei/CVE-2025-55182.yaml
```

Scan with safe detection first:

```bash
nuclei -u https://example.com -t nuclei/CVE-2025-55182-safe.yaml
```

Scan with OOB callback (requires interactsh):

```bash
nuclei -u https://example.com -t nuclei/CVE-2025-55182-oob.yaml
```

Scan list of targets with all templates:

```bash
nuclei -l targets.txt -t nuclei/ -severity critical
```

Use the workflow for detection:

```bash
nuclei -u https://example.com -w nuclei/react2shell-workflow.yaml
```

### Templates

| Scenario                        | Recommended Template          |
| ------------------------------- | ----------------------------- |
| Standard penetration test       | `CVE-2025-55182.yaml`         |
| Minimal impact / reconnaissance | `CVE-2025-55182-safe.yaml`    |
| WAF blocking response headers   | `CVE-2025-55182-oob.yaml`     |
| Windows targets                 | `CVE-2025-55182-windows.yaml` |
| Version enumeration             | `nextjs-version-detect.yaml`  |

## References

- [Wiz Blog: Critical Vulnerability in React CVE-2025-55182](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Unit 42: CVE-2025-55182 React and CVE-2025-66478 Next.js](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- [Tenable: React2Shell CVE-2025-55182](https://www.tenable.com/blog/react2shell-cve-2025-55182-react-server-components-rce)
- [Akamai: CVE-2025-55182 Deserialization RCE](https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce)

### Credits

PoC originally disclosed by [@maple3142](https://x.com/maple3142)
