import tls from "tls";
import { CheckResult, Confidence, Finding, makeFindingId, Severity } from "../schema/finding";
import { DomainResult } from "./domainResult";
import { fetchWithTimeout } from "./util";
import { guardedLookup } from "./netGuard";

/**
 * TLS / certificate check (domain mode, passive).
 *
 * Completes a TLS handshake to inspect the negotiated protocol and certificate,
 * then evaluates trust ourselves. Verification is intentionally NOT enforced at
 * connect time so that a chain the scanner's CA store can't build (e.g. behind a
 * TLS-inspecting proxy) is reported as a low-confidence trust finding rather than
 * being mistaken for a connection failure. Optionally enriched with SSL Labs.
 */

interface TlsInfo {
  connected: boolean;
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  validTo: string | null;
  validFrom: string | null;
  daysToExpiry: number | null;
  issuer: string | null;
  error?: string; // set only on genuine connection failures
}

function inspectTls(host: string, timeoutMs = 10000): Promise<TlsInfo> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
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
        });
        socket.end();
      }
    );
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
        error: message,
      });
    socket.on("error", (err) => fail(err.message));
    socket.on("timeout", () => {
      socket.destroy();
      fail("TLS handshake timed out");
    });
  });
}

async function sslLabsGrade(host: string): Promise<string | null> {
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

export function tlsAdapter(host: string, info: TlsInfo, grade: string | null): DomainResult {
  const findings: Finding[] = [];
  const checks: CheckResult[] = [];
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
      metadata: { owasp: "A02:2021-Cryptographic Failures", ...extra },
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

  // Handshake completed but the chain didn't verify against the scanner's trust
  // store — a weak signal (often a local TLS-inspecting proxy).
  if (!info.authorized) {
    finding(
      "cert-untrusted",
      "medium",
      "Certificate trust",
      "TLS certificate chain did not verify",
      `The certificate chain could not be verified by the scanner (${info.authorizationError}). This may indicate a self-signed/misconfigured chain, or simply a TLS-inspecting proxy between the scanner and the host — verify from an untrusted network before acting.`,
      info.authorizationError ?? "not verified",
      "Verify the certificate chain from an untrusted network.",
      { authorizationError: info.authorizationError, issuer: info.issuer },
      "low"
    );
  } else {
    pass("Certificate trust", `chain verified${info.issuer ? `, ${info.issuer}` : ""}`);
  }

  if (info.daysToExpiry !== null && info.daysToExpiry < 0) {
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

  return { findings, checks };
}

export async function runTlsCheck(host: string): Promise<DomainResult> {
  const info = await inspectTls(host);
  const grade = await sslLabsGrade(host);
  return tlsAdapter(host, info, grade);
}
