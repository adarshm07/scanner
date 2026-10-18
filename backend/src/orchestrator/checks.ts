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
    tools: "semgrep (registry rules + Scanner-X rules)",
    desc: "Static taint rules for injection, auth and crypto misuse.",
    est: "~30s",
  },
  {
    id: "deps",
    mode: "repo",
    name: "Dependencies",
    tools: "npm audit + osv-scanner",
    desc: "Dependencies checked against known advisories: npm via npm audit; Python, Java, Rust, Go, Ruby, PHP, .NET and yarn/pnpm via OSV-Scanner.",
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
    desc: "Security headers, cookie flags, CORS, HTTP→HTTPS redirect and HSTS preload. Includes copy-paste fixes for your server.",
    est: "~4s",
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
    name: "DNS security",
    tools: "built-in",
    desc: "SPF, DKIM, DMARC and MTA-STS for email; CAA and DNSSEC for the domain.",
    est: "~5s",
  },
  {
    id: "subdomains",
    mode: "domain",
    name: "Subdomains",
    tools: "crt.sh + DNS",
    desc: "Lists subdomains from certificate transparency logs and flags any that can be taken over (dangling CNAMEs).",
    est: "~15s",
  },
  {
    id: "exposed-files",
    mode: "domain",
    name: "Exposed sensitive files",
    tools: "HTTPS GET",
    desc: "~30 paths that should never be public: .git, .env, backups, database dumps, Spring actuator, phpinfo, source maps.",
    est: "~4s",
  },
];

export const CHECK_IDS = new Set(CHECKS.map((c) => c.id));
