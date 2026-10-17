import { Report, ReportFinding, Severity } from "../schema/finding";

/**
 * Self-contained HTML version of a report (no external requests), e.g. for GitHub Pages.
 * Everything from the report is escaped: findings carry text from the scanned code.
 */

const esc = (v: unknown): string =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const ORDER: Severity[] = ["critical", "high", "medium", "low"];
const sevOf = (f: ReportFinding): Severity => f.triage?.adjusted_severity ?? f.severity;

export interface HtmlOptions {
  /** Prefix for file links, e.g. https://github.com/o/r/blob/<sha>/ */
  linkBase?: string;
}

function safeHttpUrl(u: string): string | null {
  try {
    const url = new URL(u);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}

function location(f: ReportFinding, opts: HtmlOptions): string {
  const { file, line_start, line_end, url } = f.location;
  if (file) {
    const label = `${file}${line_start ? `:${line_start}` : ""}`;
    if (opts.linkBase) {
      const href = safeHttpUrl(
        `${opts.linkBase.replace(/\/?$/, "/")}${file.split("/").map(encodeURIComponent).join("/")}${line_start ? `#L${line_start}${line_end && line_end !== line_start ? `-L${line_end}` : ""}` : ""}`
      );
      if (href) return `<a href="${esc(href)}">${esc(label)}</a>`;
    }
    return esc(label);
  }
  if (url) {
    const href = safeHttpUrl(url);
    return href ? `<a href="${esc(href)}" rel="nofollow noopener">${esc(url)}</a>` : esc(url);
  }
  return "";
}

function finding(f: ReportFinding, opts: HtmlOptions, aiTriage: boolean): string {
  const sev = sevOf(f);
  const meta = f.metadata ?? {};
  const tags = [
    f.rule_id,
    typeof meta.cwe === "string" ? meta.cwe : null,
    f.confidence ? `${f.confidence} confidence` : null,
    f.triage && f.triage.verdict !== "needs_review" ? f.triage.verdict.replace("_", " ") : null,
    f.triage && f.triage.adjusted_severity !== f.severity ? `was ${f.severity}` : null,
  ].filter(Boolean);
  const evidence = Array.isArray(meta.evidence) ? (meta.evidence as unknown[]).map(String) : [];
  const advisory = typeof meta.advisoryUrl === "string" ? safeHttpUrl(meta.advisoryUrl) : null;
  return `
  <details class="f" ${sev === "critical" || sev === "high" ? "open" : ""}>
    <summary><span class="sev ${sev}">${sev}</span><span class="t">${esc(f.title)}</span><span class="loc">${location(f, opts)}</span></summary>
    <div class="body">
      <p class="tags">${tags.map((t) => `<code>${esc(t)}</code>`).join(" ")}</p>
      <p>${esc(f.tool_message)}</p>
      ${aiTriage && f.triage?.explanation && f.triage.explanation !== f.tool_message ? `<h4>Why it matters</h4><p>${esc(f.triage.explanation)}</p>` : ""}
      ${aiTriage && f.triage?.suggested_fix ? `<h4>Fix</h4><p>${esc(f.triage.suggested_fix)}</p>` : ""}
      ${evidence.length ? `<h4>Evidence</h4><ul class="mono">${evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : ""}
      ${f.raw_snippet ? `<pre>${esc(f.raw_snippet)}</pre>` : ""}
      ${advisory ? `<p><a href="${esc(advisory)}" rel="nofollow noopener">Advisory</a></p>` : ""}
    </div>
  </details>`;
}

export function renderHtml(report: Report, opts: HtmlOptions = {}): string {
  const all = report.categories.flatMap((c) => c.findings).sort((a, b) => ORDER.indexOf(sevOf(a)) - ORDER.indexOf(sevOf(b)));
  const s = report.stats.bySeverity;
  const p = report.policy;
  const policy = p.passed
    ? `<p class="pass">Policy passed: nothing at or above ${esc(p.failOn)}</p>`
    : `<p class="fail">Policy failed: ${esc([p.reason, p.countAtOrAbove ? `${p.countAtOrAbove} at or above ${p.failOn}` : ""].filter(Boolean).join(" · "))}</p>`;
  const ref = report.diff ? `${report.diff.baseSha.slice(0, 7)}…${report.diff.headSha.slice(0, 7)}` : report.ref.slice(0, 12);
  const triage = report.ai.triageEnabled && report.ai.provider ? `AI triage: ${report.ai.provider}` : "Triage: deterministic (no AI)";

  const checks = report.checks.length
    ? `<h2>Checks</h2><table><thead><tr><th>Group</th><th>Check</th><th>Result</th><th>Observed</th></tr></thead><tbody>${report.checks
        .map((c) => `<tr><td>${esc(c.group)}</td><td>${esc(c.name)}</td><td><span class="sev ${c.result === "finding" ? esc(c.severity ?? "low") : c.result}">${esc(c.result === "finding" ? c.severity : c.result)}</span></td><td>${esc(c.observed)}</td></tr>`)
        .join("")}</tbody></table>`
    : "";

  const fixes = report.fixes
    ? `<h2>Fix it</h2><p class="muted">${report.fixes.detected ? `Detected ${esc(report.fixes.detected)} (${esc(report.fixes.detectedFrom)}).` : "Pick your server or platform."}</p>
       <ul>${report.fixes.changes.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>
       ${report.fixes.platforms
         .map((pl, i) => `<details class="f" ${i === 0 ? "open" : ""}><summary><span class="t">${esc(pl.label)}</span><span class="loc">${esc(pl.file)}</span></summary><div class="body"><pre>${esc(pl.snippet)}</pre>${pl.notes.map((n) => `<p class="muted">${esc(n)}</p>`).join("")}</div></details>`)
         .join("")}`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>Scanner-X report · ${esc(report.target)}</title>
<style>
:root{--bg:#f7f8f9;--panel:#fff;--line:#dde1e5;--text:#1b1f23;--muted:#5d6670;--code:#eef1f4;
  --critical:#c9264a;--high:#c4621a;--medium:#9a7a00;--low:#2f6fae;--pass:#2e8b57}
@media (prefers-color-scheme:dark){:root{--bg:#0f1215;--panel:#12171a;--line:#262d33;--text:#e3e7ea;--muted:#8d979f;--code:#0a0d0f;
  --critical:#f0506e;--high:#f28c38;--medium:#d9b53c;--low:#6aa5e0;--pass:#56b982}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:24px;margin:0 0 4px;letter-spacing:-.02em;overflow-wrap:anywhere}
h2{font-size:18px;margin:36px 0 12px}
h4{margin:12px 0 4px;font-size:13px}
a{color:var(--low)}
.muted,.meta{color:var(--muted)}
.meta{display:flex;flex-wrap:wrap;gap:4px 18px;font-size:13px;margin-bottom:16px}
.pass{color:var(--pass);font-weight:600}.fail{color:var(--critical);font-weight:600}
.note{border:1px solid var(--line);background:var(--panel);padding:10px 12px;margin:8px 0;border-radius:4px}
.warn{border-color:var(--medium)}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
.counts div{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:8px 14px;min-width:96px}
.counts b{display:block;font-size:22px}
.f{background:var(--panel);border:1px solid var(--line);border-radius:4px;margin:8px 0}
.f summary{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:baseline;padding:10px 12px;cursor:pointer}
.f .t{font-weight:600;flex:1 1 280px;overflow-wrap:anywhere}
.f .loc{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);overflow-wrap:anywhere}
.body{padding:0 12px 12px;border-top:1px solid var(--line)}
.sev{font:600 11px ui-monospace,monospace;text-transform:uppercase;padding:2px 6px;border-radius:3px;border:1px solid currentColor}
.sev.critical{color:var(--critical)}.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}.sev.low{color:var(--low)}
.sev.pass{color:var(--pass)}.sev.inconclusive{color:var(--muted)}
pre,code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
pre{background:var(--code);border:1px solid var(--line);padding:10px;overflow-x:auto;border-radius:4px}
code{background:var(--code);padding:1px 4px;border-radius:3px}
.tags{margin:10px 0 4px}
table{width:100%;border-collapse:collapse;background:var(--panel);font-size:13px;display:block;overflow-x:auto}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
footer{margin-top:40px;color:var(--muted);font-size:12.5px}
</style>
</head>
<body><main>
<h1>${esc(report.target)}</h1>
<div class="meta"><span>${esc(report.mode)} scan</span><span>ref ${esc(ref)}</span>${report.diff ? `<span>${report.diff.changedFiles} files changed vs ${esc(report.diff.baseRef)}</span>` : ""}<span>${esc(new Date(report.createdAt).toUTCString())}</span><span>${esc(triage)}</span></div>
${policy}
${report.warning ? `<div class="note warn">${esc(report.warning)}</div>` : ""}
${(report.notes ?? []).map((n) => `<div class="note">${esc(n)}</div>`).join("")}
<div class="counts">${ORDER.map((k) => `<div><span class="sev ${k}">${k}</span><b>${s[k]}</b></div>`).join("")}</div>
<h2>Findings (${all.length})</h2>
${all.length ? all.map((f) => finding(f, opts, report.ai.provider !== null)).join("") : `<p class="muted">No findings.</p>`}
${fixes}
${checks}
<footer>Generated by <a href="https://github.com/adarshm07/scanner">Scanner-X</a>. Detection by gitleaks, semgrep, npm audit and OSV-Scanner; secrets are masked before anything is shown or sent to a model.</footer>
</main></body></html>
`;
}
