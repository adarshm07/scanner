import { ScanMode } from "../schema/finding";

/**
 * Per-tool check catalog (mirrors the design's scope selector). Each check maps
 * to one deterministic tool; the frontend renders these as toggle rows and the
 * pipeline runs only the selected ones.
 */
export interface CheckDef {
  id: string;
  mode: ScanMode;
  name: string;
  tools: string;
  desc: string;
  est: string;
}

export const CHECKS: CheckDef[] = [
  {
    id: "secrets",
    mode: "repo",
    name: "Secrets",
    tools: "gitleaks",
    desc: "Full working tree scanned for hardcoded credentials and tokens.",
    est: "~15s",
  },
  {
    id: "sast",
    mode: "repo",
    name: "Code (SAST)",
    tools: "semgrep p/security-audit",
    desc: "Static taint rules for injection, auth and crypto misuse.",
    est: "~30s",
  },
  {
    id: "deps",
    mode: "repo",
    name: "Dependencies",
    tools: "npm audit / osv",
    desc: "Lockfile dependencies checked against known advisories.",
    est: "~6s",
  },
  {
    id: "tls",
    mode: "domain",
    name: "TLS & certificate",
    tools: "built-in, SSL Labs",
    desc: "Protocol versions, certificate chain, expiry and trust.",
    est: "~10s",
  },
  {
    id: "headers",
    mode: "domain",
    name: "HTTP security headers",
    tools: "built-in",
    desc: "One GET to /. HSTS, CSP, X-Frame-Options and more.",
    est: "~2s",
  },
  {
    id: "csp",
    mode: "domain",
    name: "Content-Security-Policy",
    tools: "built-in",
    desc: "Grades CSP directives and common XSS bypass weaknesses.",
    est: "~1 request, instant",
  },
  {
    id: "dns",
    mode: "domain",
    name: "DNS email authentication",
    tools: "built-in",
    desc: "SPF, DKIM and DMARC records via public DNS.",
    est: "~4s",
  },
  {
    id: "subdomains",
    mode: "domain",
    name: "Subdomains",
    tools: "crt.sh",
    desc: "Passive enumeration from certificate transparency logs.",
    est: "~6s",
  },
  {
    id: "exposed-files",
    mode: "domain",
    name: "Exposed sensitive files",
    tools: "HTTPS GET",
    desc: "Checks common .git and .env paths without authentication.",
    est: "<2s",
  },
];

export const CHECK_IDS = new Set(CHECKS.map((c) => c.id));
