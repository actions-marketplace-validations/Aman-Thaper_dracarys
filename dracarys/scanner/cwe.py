"""CWE identifiers and generic remediation guidance per vulnerability class."""
from __future__ import annotations

from dracarys.domain.enums import Severity, VulnCategory

CWE: dict[VulnCategory, str] = {
    VulnCategory.SQL_INJECTION: "CWE-89",
    VulnCategory.XSS: "CWE-79",
    VulnCategory.IDOR: "CWE-639",
    VulnCategory.OPEN_REDIRECT: "CWE-601",
    VulnCategory.SENSITIVE_DATA: "CWE-200",
    VulnCategory.INFO_DISCLOSURE: "CWE-200",
    VulnCategory.VERBOSE_ERROR: "CWE-209",
    VulnCategory.EXPOSED_RESOURCE: "CWE-538",
    VulnCategory.SECURITY_MISCONFIG: "CWE-16",
    VulnCategory.CREDENTIAL_EXPOSURE: "CWE-522",
    VulnCategory.BROKEN_AUTH: "CWE-287",
    VulnCategory.PRIVILEGE_ESCALATION: "CWE-269",
    VulnCategory.PATH_TRAVERSAL: "CWE-22",
    VulnCategory.SSTI: "CWE-1336",
    VulnCategory.CORS_MISCONFIG: "CWE-942",
}

REMEDIATION: dict[VulnCategory, str] = {
    VulnCategory.SQL_INJECTION: (
        "Use parameterized queries / prepared statements for all SQL. Never build "
        "queries by concatenating user input. Apply least-privilege DB accounts."
    ),
    VulnCategory.XSS: (
        "Context-aware output encoding for all user-controlled data. Set a strict "
        "Content-Security-Policy and use frameworks that auto-escape by default."
    ),
    VulnCategory.IDOR: (
        "Enforce object-level authorization on every request: verify the caller "
        "owns or may access the referenced object; do not rely on unguessable ids."
    ),
    VulnCategory.OPEN_REDIRECT: (
        "Do not redirect to user-supplied URLs. Use an allowlist of permitted "
        "destinations or relative paths only."
    ),
    VulnCategory.SENSITIVE_DATA: (
        "Remove secrets from responses and source. Rotate any exposed credential "
        "and store secrets in a vault, never in code or client-visible responses."
    ),
    VulnCategory.VERBOSE_ERROR: (
        "Disable debug mode in production and return generic error messages. Log "
        "details server-side only."
    ),
    VulnCategory.EXPOSED_RESOURCE: (
        "Block access to sensitive paths (.git, .env, backups, admin/actuator "
        "endpoints) at the server/proxy and remove them from the web root."
    ),
    VulnCategory.SECURITY_MISCONFIG: (
        "Add the missing security headers at the application or edge (CSP, HSTS, "
        "X-Content-Type-Options, X-Frame-Options, Referrer-Policy)."
    ),
    VulnCategory.INFO_DISCLOSURE: (
        "Do not expose internal detail to unauthenticated clients; gate diagnostics "
        "behind authentication and strip sensitive fields."
    ),
    VulnCategory.PATH_TRAVERSAL: (
        "Never build filesystem paths from user input. Resolve the candidate path and "
        "verify it stays inside the intended directory, or map the input to an "
        "allowlist of known filenames."
    ),
    VulnCategory.SSTI: (
        "Never pass user input to a template engine as template source. Render "
        "untrusted values as data through the engine's context/variables, and use a "
        "sandboxed or logic-less template for any user-supplied template."
    ),
    VulnCategory.CORS_MISCONFIG: (
        "Do not reflect arbitrary Origin headers. Serve "
        "Access-Control-Allow-Credentials: true only alongside an explicit allowlist "
        "of trusted origins, and never together with a wildcard or a 'null' origin."
    ),
}

DEFAULT_SEVERITY: dict[VulnCategory, Severity] = {
    VulnCategory.SQL_INJECTION: Severity.CRITICAL,
    VulnCategory.XSS: Severity.HIGH,
    VulnCategory.IDOR: Severity.HIGH,
    VulnCategory.OPEN_REDIRECT: Severity.MEDIUM,
    VulnCategory.SENSITIVE_DATA: Severity.HIGH,
    VulnCategory.VERBOSE_ERROR: Severity.LOW,
    VulnCategory.EXPOSED_RESOURCE: Severity.HIGH,
    VulnCategory.SECURITY_MISCONFIG: Severity.LOW,
    VulnCategory.INFO_DISCLOSURE: Severity.MEDIUM,
    VulnCategory.PATH_TRAVERSAL: Severity.HIGH,
    VulnCategory.SSTI: Severity.CRITICAL,
    VulnCategory.CORS_MISCONFIG: Severity.MEDIUM,
}


def cwe_for(cat: VulnCategory) -> str:
    return CWE.get(cat, "CWE-0")


def remediation_for(cat: VulnCategory) -> str:
    return REMEDIATION.get(cat, "Review and remediate per OWASP ASVS guidance.")
