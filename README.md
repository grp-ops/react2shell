# React2Shell

CLI tool + Nuclei templates for detecting two critical RCE vulnerabilities in React Server Components and Next.js Server Actions.  
The scanner was rewritten after the extent of the vulnerability became apparent.

## Vulnerability Overview

**CVE-2025-55182 – React Server Components Deserialization RCE**  
A flaw in the React Flight deserialization process allows user-controlled references to resolve to server functions, leading to remote code execution.  
Affects React **19.0.0–19.2.0**.

**CVE-2025-66478 – Next.js Server Actions RCE**  
Next.js inherits the same unsafe deserialization behavior when handling Server Actions, resulting in the same RCE pathway.  
Affects Next.js **14.3.0-canary.77 through 16.0.6**.

Both are rated **CVSS 10.0** due to trivial exploitability and full RCE impact.
Updated releases of React and Next.js provide patches.

## Scanner

- RCE PoC or safe, non-exploit detection  
- Version-only fingerprinting to avoid unnecessary checks  
- Out-of-band RCE confirmation using DNS/HTTP callbacks  
  (fully compatible with Burp Collaborator, interactsh, etc.)  
- WAF bypass mode with adjustable padding  
- Multiple payload variants for evasion testing  
- Nuclei templates included

## Usage

Fingerprint only:

    python3 scanner.py -u https://example.com --fingerprint-only

Callback detection  
(use any DNS/HTTP listener, including Burp Collaborator):

    python3 scanner.py -u https://example.com --callback-url https://your-id.oast.pro/r2s

Nuclei workflow:

    nuclei -u https://example.com -w nuclei/react2shell-workflow.yaml

## Research Credits

Vulnerability discovery and PoC research by:  
- **maple3142**  
- Security teams at **Wiz**, **Palo Alto Unit 42**, **Tenable**, and **Akamai**

## References

- Wiz: https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182  
- Unit 42: https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/  
- Tenable: https://www.tenable.com/blog/react2shell-cve-2025-55182-react-server-components-rce  
- Akamai: https://www.akamai.com/blog/security-research/cve-2025-55182-react-nextjs-server-functions-deserialization-rce