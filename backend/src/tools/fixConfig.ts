/**
 * Copy-paste fixes for the header, cookie and HTTPS findings of a domain scan, written for
 * the server or platform the site appears to run on (detected from response headers) and
 * for the other common ones. Deterministic: the AI triage explains findings; these
 * snippets are generated from rules, so they're the same every run.
 */

export interface FixInput {
  server: string | null;
  poweredBy: string | null;
  /** Platform-identifying response headers that were present (x-vercel-id, cf-ray, ...). */
  platformHints: string[];
  /** Missing security headers (lowercase names). */
  missingHeaders: string[];
  weakHsts: boolean;
  hideServerVersion: boolean;
  hidePoweredBy: boolean;
  httpRedirect: boolean;
  /** Cookies that need Secure/HttpOnly/SameSite. */
  cookies: string[];
  /** No Content-Security-Policy header at all. */
  csp: boolean;
}

export interface FixSnippet {
  id: PlatformId;
  label: string;
  /** Where the snippet goes. */
  file: string;
  language: "nginx" | "apache" | "xml" | "javascript" | "json" | "text";
  snippet: string;
  notes: string[];
}

export interface FixPlan {
  /** Platform detected from the response, if any. */
  detected: PlatformId | null;
  detectedFrom: string | null;
  /** One line per change the snippets make. */
  changes: string[];
  /** Detected platform first. */
  platforms: FixSnippet[];
}

export type PlatformId = "nginx" | "apache" | "iis" | "express" | "nextjs" | "vercel" | "netlify" | "cloudflare";

const VALUES: Record<string, { name: string; value: string }> = {
  "strict-transport-security": { name: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
  "x-frame-options": { name: "X-Frame-Options", value: "SAMEORIGIN" },
  "x-content-type-options": { name: "X-Content-Type-Options", value: "nosniff" },
  "referrer-policy": { name: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  "permissions-policy": { name: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
};
/** A starting policy, in report-only mode so it can't break the site before it's tuned. */
const CSP_REPORT_ONLY = {
  name: "Content-Security-Policy-Report-Only",
  value: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
};

export function detectPlatform(input: FixInput): { id: PlatformId; from: string } | null {
  const server = input.server ?? "";
  const powered = input.poweredBy ?? "";
  const hint = (h: string) => input.platformHints.includes(h);
  if (hint("x-vercel-id") || /vercel/i.test(server)) return { id: "vercel", from: hint("x-vercel-id") ? "x-vercel-id header" : `Server: ${server}` };
  if (hint("x-nf-request-id") || /netlify/i.test(server)) return { id: "netlify", from: hint("x-nf-request-id") ? "x-nf-request-id header" : `Server: ${server}` };
  if (/next\.js/i.test(powered)) return { id: "nextjs", from: `X-Powered-By: ${powered}` };
  if (/express/i.test(powered)) return { id: "express", from: `X-Powered-By: ${powered}` };
  if (/microsoft-iis/i.test(server) || /asp\.net/i.test(powered)) return { id: "iis", from: server ? `Server: ${server}` : `X-Powered-By: ${powered}` };
  if (/nginx|openresty/i.test(server)) return { id: "nginx", from: `Server: ${server}` };
  if (/apache/i.test(server)) return { id: "apache", from: `Server: ${server}` };
  if (/cloudflare/i.test(server) || hint("cf-ray")) return { id: "cloudflare", from: server ? `Server: ${server}` : "cf-ray header" };
  return null;
}

function headerList(input: FixInput): { name: string; value: string }[] {
  const names = new Set(input.missingHeaders);
  if (input.weakHsts) names.add("strict-transport-security");
  const list = [...names].filter((n) => VALUES[n]).map((n) => VALUES[n]);
  if (input.csp) list.push(CSP_REPORT_ONLY);
  return list;
}

const q = (v: string) => v.replace(/"/g, '\\"');

function nginx(host: string, input: FixInput, headers: { name: string; value: string }[]): FixSnippet {
  const lines = [`# Inside the server { } block that serves https://${host}`];
  for (const h of headers) lines.push(`add_header ${h.name} "${q(h.value)}" always;`);
  if (input.hideServerVersion) lines.push("server_tokens off;");
  if (input.hidePoweredBy) lines.push("proxy_hide_header X-Powered-By;");
  if (input.cookies.length) lines.push("proxy_cookie_flags ~ secure httponly samesite=lax;   # nginx 1.19.3+, cookies from proxy_pass apps");
  if (input.httpRedirect) {
    lines.push("", "# Redirect plain HTTP to HTTPS", "server {", "    listen 80;", "    listen [::]:80;", `    server_name ${host};`, "    return 301 https://$host$request_uri;", "}");
  }
  return {
    id: "nginx",
    label: "nginx",
    file: `/etc/nginx/sites-available/${host} (then: nginx -t && systemctl reload nginx)`,
    language: "nginx",
    snippet: lines.join("\n"),
    notes: ["A location { } block with its own add_header drops the server-level ones; repeat them there."],
  };
}

function apache(host: string, input: FixInput, headers: { name: string; value: string }[]): FixSnippet {
  const lines = ["# .htaccess or the <VirtualHost *:443> block (needs mod_headers)", "<IfModule mod_headers.c>"];
  for (const h of headers) lines.push(`  Header always set ${h.name} "${q(h.value)}"`);
  if (input.hidePoweredBy) lines.push("  Header always unset X-Powered-By");
  if (input.cookies.length) lines.push('  Header always edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Lax"');
  lines.push("</IfModule>");
  if (input.httpRedirect) {
    lines.push("", "# Redirect plain HTTP to HTTPS (needs mod_rewrite)", "RewriteEngine On", "RewriteCond %{HTTPS} off", "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]");
  }
  if (input.hideServerVersion) lines.push("", "# httpd.conf / apache2.conf only (not .htaccess)", "ServerTokens Prod", "ServerSignature Off");
  const notes = ["Reload Apache after editing the main config: apachectl configtest && apachectl graceful."];
  if (input.cookies.length) notes.push("The Set-Cookie edit appends flags to every cookie; if your app already sets some of them, set the flags in the app instead.");
  return { id: "apache", label: "Apache", file: ".htaccess or the site's VirtualHost", language: "apache", snippet: lines.join("\n"), notes };
}

function iis(_host: string, input: FixInput, headers: { name: string; value: string }[]): FixSnippet {
  const lines = ["<configuration>", "  <system.webServer>", "    <httpProtocol>", "      <customHeaders>"];
  if (input.hidePoweredBy) lines.push('        <remove name="X-Powered-By" />');
  for (const h of headers) lines.push(`        <add name="${h.name}" value="${h.value.replace(/"/g, "&quot;")}" />`);
  lines.push("      </customHeaders>", "    </httpProtocol>");
  if (input.hideServerVersion) lines.push("    <security>", '      <requestFiltering removeServerHeader="true" />', "    </security>");
  if (input.httpRedirect) {
    lines.push(
      "    <rewrite>", "      <rules>", '        <rule name="HTTPS" stopProcessing="true">', '          <match url="(.*)" />',
      '          <conditions><add input="{HTTPS}" pattern="off" /></conditions>',
      '          <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />',
      "        </rule>", "      </rules>", "    </rewrite>"
    );
  }
  lines.push("  </system.webServer>");
  if (input.cookies.length) lines.push("  <system.web>", '    <httpCookies requireSSL="true" httpOnlyCookies="true" sameSite="Lax" />', "  </system.web>");
  lines.push("</configuration>");
  const notes = ["Merge into the existing web.config rather than replacing it."];
  if (input.httpRedirect) notes.push("The redirect rule needs the IIS URL Rewrite module.");
  if (input.hideServerVersion) notes.push("removeServerHeader needs IIS 10 or later.");
  return { id: "iis", label: "IIS", file: "web.config", language: "xml", snippet: lines.join("\n"), notes };
}

function express(_host: string, input: FixInput, headers: { name: string; value: string }[]): FixSnippet {
  const lines = ["// npm install helmet", 'const helmet = require("helmet");', ""];
  if (input.hidePoweredBy) lines.push('app.disable("x-powered-by");');
  lines.push(
    "app.use(",
    "  helmet({",
    "    strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },",
    '    xFrameOptions: { action: "sameorigin" },',
    '    referrerPolicy: { policy: "strict-origin-when-cross-origin" },',
    input.csp
      ? "    contentSecurityPolicy: { useDefaults: true, reportOnly: true }, // tune, then drop reportOnly"
      : "    contentSecurityPolicy: false, // you already send a CSP",
    "  })",
    ");"
  );
  if (headers.some((h) => h.name === "Permissions-Policy")) {
    lines.push("", "// helmet doesn't set Permissions-Policy", "app.use((req, res, next) => {", `  res.setHeader("Permissions-Policy", "${VALUES["permissions-policy"].value}");`, "  next();", "});");
  }
  if (input.httpRedirect) {
    lines.push("", "// Redirect HTTP to HTTPS (behind a proxy or load balancer)", 'app.set("trust proxy", 1);', "app.use((req, res, next) =>", "  req.secure ? next() : res.redirect(301, `https://${req.headers.host}${req.originalUrl}`)", ");");
  }
  if (input.cookies.length) {
    lines.push("", `// Cookies (${input.cookies.join(", ")}): set the flags wherever they're created`, 'res.cookie(name, value, { secure: true, httpOnly: true, sameSite: "lax" });', '// express-session: session({ cookie: { secure: true, httpOnly: true, sameSite: "lax" }, ... })');
  }
  return { id: "express", label: "Express", file: "where the app is created (app.js / server.js), before the routes", language: "javascript", snippet: lines.join("\n"), notes: ["Run helmet before your routes so every response gets the headers."] };
}

function nextjs(_host: string, input: FixInput, headers: { name: string; value: string }[]): FixSnippet {
  const lines = ["// next.config.js", "const securityHeaders = ["];
  for (const h of headers) lines.push(`  { key: "${h.name}", value: "${q(h.value)}" },`);
  lines.push("];", "", "module.exports = {");
  if (input.hidePoweredBy) lines.push("  poweredByHeader: false,");
  lines.push("  async headers() {", '    return [{ source: "/:path*", headers: securityHeaders }];', "  },", "};");
  const notes = ["Merge into your existing next.config.js export."];
  if (input.cookies.length) notes.push(`Cookies (${input.cookies.join(", ")}): pass { secure: true, httpOnly: true, sameSite: "lax" } where they're set (cookies().set(...) or your auth library's cookie options).`);
  if (input.httpRedirect) notes.push("HTTPS redirects are handled by the host (Vercel does this automatically); on a custom server, redirect in front of Next.js.");
  return { id: "nextjs", label: "Next.js", file: "next.config.js", language: "javascript", snippet: lines.join("\n"), notes };
}

function vercel(_host: string, input: FixInput, headers: { name: string; value: string }[]): FixSnippet {
  const json = { headers: [{ source: "/(.*)", headers: headers.map((h) => ({ key: h.name, value: h.value })) }] };
  const notes = ["Merge into vercel.json at the project root and redeploy.", "Vercel already redirects HTTP to HTTPS."];
  if (input.hidePoweredBy) notes.push("For Next.js, also set poweredByHeader: false in next.config.js.");
  if (input.cookies.length) notes.push(`Cookies (${input.cookies.join(", ")}) must be fixed in the app code where they're set.`);
  return { id: "vercel", label: "Vercel", file: "vercel.json", language: "json", snippet: JSON.stringify(json, null, 2), notes };
}

function headersFile(headers: { name: string; value: string }[]): string {
  return ["/*", ...headers.map((h) => `  ${h.name}: ${h.value}`)].join("\n");
}

function netlify(_host: string, input: FixInput, headers: { name: string; value: string }[]): FixSnippet {
  const notes = ["Put _headers in the publish directory (e.g. public/ or dist/) and redeploy.", "Netlify redirects HTTP to HTTPS once a certificate is active."];
  if (input.cookies.length) notes.push(`Cookies (${input.cookies.join(", ")}) must be fixed where they're set (functions or the app).`);
  return { id: "netlify", label: "Netlify", file: "_headers (publish directory)", language: "text", snippet: headersFile(headers), notes };
}

function cloudflare(_host: string, input: FixInput, headers: { name: string; value: string }[]): FixSnippet {
  const notes = [
    "Cloudflare Pages: put this _headers file in the build output directory.",
    "Proxied site (orange cloud): add the same headers under Rules → Transform Rules → Modify Response Header, or fix them at your origin server.",
  ];
  if (input.httpRedirect) notes.push("Turn on SSL/TLS → Edge Certificates → Always Use HTTPS.");
  if (input.cookies.length) notes.push(`Cookies (${input.cookies.join(", ")}) must be fixed at the origin where they're set.`);
  return { id: "cloudflare", label: "Cloudflare", file: "_headers (Pages) or Transform Rules", language: "text", snippet: headersFile(headers), notes };
}

const BUILDERS: Record<PlatformId, (host: string, input: FixInput, headers: { name: string; value: string }[]) => FixSnippet> = {
  nginx, apache, iis, express, nextjs, vercel, netlify, cloudflare,
};

/** Null when there's nothing these snippets can fix. */
export function buildFixPlan(host: string, input: FixInput): FixPlan | null {
  const headers = headerList(input);
  const changes: string[] = [];
  const added = headers.filter((h) => h.name !== CSP_REPORT_ONLY.name).map((h) => h.name);
  if (added.length) changes.push(`Add ${added.join(", ")}${input.weakHsts ? " (HSTS with a 1-year max-age)" : ""}`);
  if (input.csp) changes.push("Start a Content-Security-Policy in report-only mode");
  if (input.httpRedirect) changes.push("Redirect HTTP to HTTPS");
  if (input.hideServerVersion || input.hidePoweredBy) changes.push("Hide server and framework versions");
  if (input.cookies.length) changes.push(`Set Secure, HttpOnly and SameSite on cookies: ${input.cookies.join(", ")}`);
  if (changes.length === 0) return null;

  const detected = detectPlatform(input);
  const order: PlatformId[] = ["nginx", "apache", "express", "nextjs", "vercel", "netlify", "cloudflare", "iis"];
  if (detected) order.splice(order.indexOf(detected.id), 1), order.unshift(detected.id);
  return {
    detected: detected?.id ?? null,
    detectedFrom: detected?.from ?? null,
    changes,
    platforms: order.map((id) => BUILDERS[id](host, input, headers)),
  };
}
