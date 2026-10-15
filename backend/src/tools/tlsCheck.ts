import tls from "tls";
import net from "net";
import { CheckResult, Confidence, Finding, makeFindingId, Severity } from "../schema/finding";
import { DomainResult } from "./domainResult";
import { fetchWithTimeout } from "./util";
import { assertIpLiteralAllowed, guardedLookup } from "./netGuard";

/**
 * TLS / certificate check (domain mode, passive).
 *
 * Completes a TLS handshake, then evaluates the certificate ourselves. Verification is
 * NOT enforced at connect time, so a chain the scanner can't verify is still inspected:
 * the full chain, the hostname match and the verification error are captured and used to
 * diagnose WHY trust failed (a TLS-inspecting proxy on the scanner's network, a
 * self-signed or private-CA certificate, a missing intermediate, ...). That evidence is
 * shown on the finding and given to triage, instead of asking the user to go and check.
 */

export interface ChainCert {
  subject: string;
  issuer: string;
  selfSigned: boolean;
  validTo: string | null;
}

export interface TlsInfo {
  connected: boolean;
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  validTo: string | null;
  validFrom: string | null;
  daysToExpiry: number | null;
  issuer: string | null;
  /** Leaf first, root (or last certificate the server sent) last. */
  chain: ChainCert[];
  /** Names the leaf certificate is valid for (subjectAltName DNS/IP entries). */
  altNames: string[];
  /** Set when the certificate doesn't cover the hostname. */
  hostnameError: string | null;
  error?: string; // set only on genuine connection failures
}

/** "host" or "host:port" (port only for local fixtures, see normalizeDomain). */
function splitHostPort(target: string): { hostname: string; port: number } {
  const m = /^(.*):(\d{1,5})$/.exec(target);
  return m ? { hostname: m[1], port: Number(m[2]) } : { hostname: target, port: 443 };
}

function certName(name: tls.Certificate | undefined): string {
  if (!name) return "?";
  const cn = (name as unknown as Record<string, unknown>).CN;
  const o = (name as unknown as Record<string, unknown>).O;
  const pick = (v: unknown) => (Array.isArray(v) ? String(v[0]) : typeof v === "string" ? v : "");
  return pick(cn) || pick(o) || "?";
}

function readChain(socket: tls.TLSSocket): ChainCert[] {
  const out: ChainCert[] = [];
  const seen = new Set<string>();
  let cert = socket.getPeerCertificate(true) as tls.DetailedPeerCertificate | undefined;
  while (cert && cert.fingerprint256 && !seen.has(cert.fingerprint256)) {
    seen.add(cert.fingerprint256);
    const subject = certName(cert.subject);
    const issuer = certName(cert.issuer);
    const issuerCert = cert.issuerCertificate as tls.DetailedPeerCertificate | undefined;
    const selfIssued = !issuerCert || issuerCert === cert || issuerCert.fingerprint256 === cert.fingerprint256;
    out.push({
      subject,
      issuer,
      selfSigned: selfIssued && subject === issuer,
      validTo: cert.valid_to ?? null,
    });
    if (selfIssued) break;
    cert = issuerCert;
  }
  return out;
}

function altNamesOf(cert: tls.PeerCertificate | undefined): string[] {
  const raw = cert?.subjectaltname ?? "";
  return raw
    .split(/,\s*/)
    .map((s) => s.replace(/^(DNS|IP Address):/, "").trim())
    .filter(Boolean);
}

function inspectTls(target: string, timeoutMs = 10000): Promise<TlsInfo> {
  const { hostname, port } = splitHostPort(target);
  return new Promise((resolve) => {
    const fail = (message: string) =>
      resolve({
        connected: false,
        authorized: false,
        authorizationError: null,
        protocol: null,
        validTo: null,
        validFrom: null,
        daysToExpiry: null,
        issuer: null,
        chain: [],
        altNames: [],
        hostnameError: null,
        error: message,
      });
    try {
      assertIpLiteralAllowed(hostname);
    } catch (err) {
      return fail((err as Error).message);
    }
    const socket = tls.connect(
      {
        host: hostname,
        port,
        // SNI must be a DNS name, never an IP literal.
        ...(net.isIP(hostname) ? {} : { servername: hostname }),
        timeout: timeoutMs,
        lookup: guardedLookup,
        // Inspect the cert ourselves; don't let Node's trust store abort the
        // handshake and hide the certificate from us.
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const validTo = cert?.valid_to ?? null;
        const daysToExpiry = validTo
          ? Math.round((new Date(validTo).getTime() - Date.now()) / 86400000)
          : null;
        // Node does not report a hostname mismatch in authorizationError; check it explicitly.
        const identityError = cert && Object.keys(cert).length ? tls.checkServerIdentity(hostname, cert) : undefined;
        resolve({
          connected: true,
          authorized: socket.authorized,
          authorizationError: socket.authorized
            ? null
            : String(socket.authorizationError ?? "unknown"),
          protocol: socket.getProtocol(),
          validTo,
          validFrom: cert?.valid_from ?? null,
          daysToExpiry,
          issuer: typeof cert?.issuer?.O === "string" ? cert.issuer.O : null,
          chain: readChain(socket),
          altNames: altNamesOf(cert),
          hostnameError: identityError ? identityError.message : null,
        });
        socket.end();
      }
    );
    socket.on("error", (err) => fail(err.message));
    socket.on("timeout", () => {
      socket.destroy();
      fail("TLS handshake timed out");
    });
  });
}

async function sslLabsGrade(host: string): Promise<string | null> {
  // Local fixtures (host:port) are not publicly reachable.
  if (host.includes(":")) return null;
  try {
    const res = await fetchWithTimeout(
      `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}&fromCache=on`,
      { timeoutMs: 8000 }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as {
      endpoints?: { grade?: string }[];
    };
    return data.endpoints?.[0]?.grade ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- diagnosis

/** Root/intermediate names used by HTTPS-inspecting proxies, VPNs and antivirus products. */
const PROXY_NAMES =
  /zscaler|netskope|palo ?alto|fortinet|fortigate|forcepoint|websense|blue ?coat|symantec web|cisco umbrella|umbrella|sophos|kaspersky|avast|\bavg\b|eset|bitdefender|mcafee web|check ?point|cloudflare (gateway|for teams)|menlo|lightspeed|securly|goguardian|mitmproxy|charles proxy|fiddler|burp/i;

export type TrustCause =
  | "inspection-proxy"
  | "self-signed"
  | "missing-intermediate"
  | "private-ca"
  | "expired-chain"
  | "unknown";

export interface TrustDiagnosis {
  cause: TrustCause;
  /** Name of the certificate that explains the cause (proxy product, private root, ...). */
  culprit: string | null;
  /** True when SSL Labs (a public vantage point) reports the site as trusted. */
  publiclyTrusted: boolean;
}

/** Work out why chain verification failed, from the error code, the chain and SSL Labs. */
export function diagnoseTrust(code: string, chain: ChainCert[], grade: string | null): TrustDiagnosis {
  const publiclyTrusted = grade !== null && /^[A-F][+-]?$/.test(grade);
  const proxyCert = chain.find((c) => PROXY_NAMES.test(c.subject) || PROXY_NAMES.test(c.issuer));
  if (proxyCert) {
    const name = PROXY_NAMES.test(proxyCert.issuer) ? proxyCert.issuer : proxyCert.subject;
    return { cause: "inspection-proxy", culprit: name, publiclyTrusted };
  }
  const root = chain[chain.length - 1];
  if (publiclyTrusted) {
    // The public internet sees a trusted chain, so something on the scanner's side differs.
    return { cause: "inspection-proxy", culprit: root?.issuer ?? null, publiclyTrusted };
  }
  if (code === "DEPTH_ZERO_SELF_SIGNED_CERT") {
    return { cause: "self-signed", culprit: chain[0]?.subject ?? null, publiclyTrusted };
  }
  if (
    (code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" || code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY") &&
    chain.length <= 1
  ) {
    return { cause: "missing-intermediate", culprit: chain[0]?.issuer ?? null, publiclyTrusted };
  }
  if (code === "SELF_SIGNED_CERT_IN_CHAIN" || code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY") {
    return { cause: "private-ca", culprit: root?.selfSigned ? root.subject : root?.issuer ?? null, publiclyTrusted };
  }
  if (code === "CERT_HAS_EXPIRED") {
    return { cause: "expired-chain", culprit: null, publiclyTrusted };
  }
  return { cause: "unknown", culprit: null, publiclyTrusted };
}

/** "example.com ← R11 ← ISRG Root X1 (self-signed)" */
export function formatChain(chain: ChainCert[]): string {
  if (chain.length === 0) return "no certificates received";
  return chain.map((c) => `${c.subject}${c.selfSigned ? " (self-signed)" : ""}`).join(" ← ");
}

function verifyCommand(host: string): string {
  const { hostname, port } = splitHostPort(host);
  const sni = net.isIP(hostname) ? "" : ` -servername ${hostname}`;
  return `openssl s_client -connect ${hostname}:${port}${sni} -showcerts </dev/null 2>/dev/null | grep -E '^ *[0-9] s:|i:'`;
}

// ---------------------------------------------------------------- adapter

export function tlsAdapter(host: string, info: TlsInfo, grade: string | null): DomainResult {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
  const notes: string[] = [];
  const url = `https://${host}`;
  const G = "TLS";

  const finding = (
    check: string,
    severity: Severity,
    name: string,
    title: string,
    message: string,
    observed: string,
    remediation: string,
    extra: Record<string, unknown> = {},
    confidence: Confidence = "high"
  ) => {
    findings.push({
      skill: `tls-${check}`,
      category: "domain",
      finding_id: makeFindingId({ domain: host, check, rule_id: check }),
      rule_id: check,
      severity,
      confidence,
      title,
      location: { url },
      raw_snippet: null,
      tool_message: message,
      metadata: { owasp: "A02:2021-Cryptographic Failures", remediation, ...extra },
    });
    checks.push({ group: G, name, result: "finding", severity, observed, remediation, source: "tls" });
  };
  const pass = (name: string, observed: string) =>
    checks.push({ group: G, name, result: "pass", observed, source: "tls" });

  // Genuine connection failure only — the handshake never completed.
  if (!info.connected) {
    finding(
      "handshake-failed",
      "high",
      "Handshake",
      "TLS handshake failed",
      `Could not establish a TLS connection: ${info.error}`,
      info.error ?? "connection failed",
      "Confirm the host serves HTTPS on port 443.",
      { error: info.error }
    );
    return { findings, checks };
  }

  const weak = ["TLSv1", "TLSv1.1", "SSLv3"];
  if (info.protocol && weak.includes(info.protocol)) {
    finding(
      "weak-protocol",
      "high",
      "TLS protocol",
      `Weak TLS protocol negotiated (${info.protocol})`,
      `Server negotiated ${info.protocol}; TLS 1.2+ is recommended.`,
      `${info.protocol} negotiated`,
      "Disable TLS 1.1 and older; require TLS 1.2+.",
      { protocol: info.protocol }
    );
  } else {
    pass("TLS protocol", `${info.protocol ?? "TLS"} negotiated`);
  }

  const chainText = formatChain(info.chain);
  const gradeText = grade ? `SSL Labs (public internet): grade ${grade}` : "SSL Labs: no cached public result";
  const evidenceBase = [
    `Verification error: ${info.authorizationError ?? "none"}`,
    `Chain received: ${chainText}`,
    gradeText,
  ];
  const evidenceMeta = (cause: string) => ({
    cause,
    authorizationError: info.authorizationError,
    chain: info.chain,
    sslLabsGrade: grade,
    evidence: evidenceBase,
    verifyCommand: verifyCommand(host),
  });

  const leafExpired = info.daysToExpiry !== null && info.daysToExpiry < 0;

  if (info.authorized) {
    pass("Certificate trust", `chain verified: ${chainText}`);
  } else if (info.authorizationError === "CERT_HAS_EXPIRED" && leafExpired) {
    // The expiry finding below covers this; don't report the same problem twice.
    pass("Certificate trust", `chain otherwise valid: ${chainText}`);
  } else {
    const d = diagnoseTrust(info.authorizationError ?? "", info.chain, grade);
    const culprit = d.culprit ?? "an unknown certificate";
    switch (d.cause) {
      case "inspection-proxy": {
        // The scanner's own network re-signs HTTPS: not a property of the target site.
        const why = PROXY_NAMES.test(culprit)
          ? `the chain is signed by "${culprit}", an HTTPS-inspection product`
          : `SSL Labs reports the site as trusted (grade ${grade}) from the public internet`;
        checks.push({
          group: G,
          name: "Certificate trust",
          result: "inconclusive",
          observed: `intercepted on the scanner's network: ${chainText}`,
          remediation:
            "Not a site problem. Scan from another network, or trust the proxy's root: NODE_EXTRA_CA_CERTS=/path/to/proxy-root.pem.",
          source: "tls",
        });
        notes.push(
          `Certificate trust for ${host} could not be assessed: HTTPS from the scanner is intercepted (${why}). No finding was raised.`
        );
        break;
      }
      case "self-signed":
        finding(
          "cert-self-signed",
          "high",
          "Certificate trust",
          "Certificate is self-signed",
          `${host} presents a self-signed certificate (${chainText}). Every browser shows a security warning, API clients refuse to connect, and users who click through can't tell a real server from an impostor.`,
          `self-signed: ${chainText}`,
          "Replace it with a certificate from a public CA, e.g. Let's Encrypt: `certbot --nginx -d <host>`.",
          evidenceMeta(d.cause)
        );
        break;
      case "missing-intermediate":
        finding(
          "cert-missing-intermediate",
          "medium",
          "Certificate trust",
          "Server doesn't send its intermediate certificate",
          `${host} sends only its own certificate (${chainText}); the intermediate issued by "${culprit}" is missing. Most browsers recover by downloading it, but curl, Android apps, webhooks and API clients fail to connect.`,
          `incomplete chain: ${chainText}`,
          "Serve the full chain, e.g. nginx `ssl_certificate .../fullchain.pem;` (not cert.pem), then reload.",
          evidenceMeta(d.cause)
        );
        break;
      case "private-ca":
        finding(
          "cert-private-ca",
          "medium",
          "Certificate trust",
          "Certificate chain ends at a root that isn't publicly trusted",
          `The chain ends at "${culprit}" (${chainText}), which isn't in the public trust store. That's normal for internal-only hosts, but public visitors get a security warning. If you recognize "${culprit}" as your company proxy, VPN or antivirus, this is the scanner's network rather than the site.`,
          `untrusted root: ${culprit}`,
          "Public sites: use a certificate from a public CA. Internal hosts: distribute the private root to clients.",
          evidenceMeta(d.cause),
          "medium"
        );
        break;
      case "expired-chain":
        finding(
          "cert-chain-expired",
          "high",
          "Certificate trust",
          "A certificate in the chain has expired",
          `The leaf certificate is valid, but another certificate in the chain has expired (${chainText}). Clients reject the connection.`,
          `expired certificate in chain: ${chainText}`,
          "Re-download the current intermediate bundle from your CA and redeploy the full chain.",
          evidenceMeta(d.cause)
        );
        break;
      default:
        finding(
          "cert-untrusted",
          "medium",
          "Certificate trust",
          "TLS certificate chain did not verify",
          `The chain could not be verified (${info.authorizationError}). Chain received: ${chainText}.`,
          info.authorizationError ?? "not verified",
          "Compare the chain with your CA's documentation and make sure the server sends the full chain.",
          evidenceMeta(d.cause),
          "low"
        );
    }
  }

  if (info.hostnameError) {
    finding(
      "cert-hostname-mismatch",
      "high",
      "Hostname",
      "Certificate is not valid for this hostname",
      `The certificate does not cover ${splitHostPort(host).hostname}. It is valid for: ${info.altNames.join(", ") || "no names"}. Browsers show a warning and clients refuse to connect.`,
      `covers: ${info.altNames.slice(0, 5).join(", ") || "none"}`,
      "Reissue the certificate with this hostname in its subjectAltName (e.g. `certbot -d <host> -d www.<host>`).",
      { altNames: info.altNames, evidence: [`Certificate names: ${info.altNames.join(", ") || "none"}`], verifyCommand: verifyCommand(host) }
    );
  } else if (info.altNames.length) {
    pass("Hostname", `covered by certificate (${info.altNames.length} ${info.altNames.length === 1 ? "name" : "names"})`);
  }

  if (leafExpired) {
    finding(
      "cert-expired",
      "critical",
      "Expiry",
      "TLS certificate has expired",
      `Certificate expired on ${info.validTo}.`,
      `expired ${info.validTo}`,
      "Renew and deploy a valid certificate immediately.",
      { validTo: info.validTo }
    );
  } else if (info.daysToExpiry !== null && info.daysToExpiry < 21) {
    finding(
      "cert-expiring",
      "medium",
      "Expiry",
      `TLS certificate expires in ${info.daysToExpiry} days`,
      `Certificate valid until ${info.validTo}. Renew before expiry.`,
      `not after ${info.validTo}, ${info.daysToExpiry} days`,
      "Renew before expiry (automate renewal).",
      { validTo: info.validTo, daysToExpiry: info.daysToExpiry }
    );
  } else if (info.validTo) {
    pass("Expiry", `not after ${info.validTo}${info.daysToExpiry !== null ? `, ${info.daysToExpiry} days` : ""}`);
  }

  if (grade && /^[CDEFT]/.test(grade)) {
    finding(
      "ssllabs-low-grade",
      "medium",
      "SSL Labs grade",
      `SSL Labs grade ${grade}`,
      `Public SSL Labs assessment returned grade ${grade}.`,
      `grade ${grade}`,
      "Review the SSL Labs report and harden the configuration.",
      { grade }
    );
  } else if (grade) {
    pass("SSL Labs grade", `grade ${grade}`);
  }

  return { findings, checks, ...(notes.length ? { notes } : {}) };
}

export async function runTlsCheck(host: string): Promise<DomainResult> {
  const info = await inspectTls(host);
  const grade = await sslLabsGrade(host);
  return tlsAdapter(host, info, grade);
}
