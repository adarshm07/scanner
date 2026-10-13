import { promises as fs } from "fs";
import path from "path";
import { Finding } from "../schema/finding";

/**
 * Step 3 of the pipeline (Spec Section 5.3): snippet hydration.
 *
 * For findings that survived filtering, read a ~20-line window around line_start
 * from the file (repo mode only) and populate raw_snippet. This is the main
 * token-saving step — never read whole files, and only hydrate survivors.
 */

const WINDOW = 10; // lines above and below line_start (~20 total)

export async function hydrateSnippets(
  findings: Finding[],
  repoDir: string
): Promise<void> {
  await Promise.all(
    findings.map(async (finding) => {
      const file = finding.location.file;
      const line = finding.location.line_start;
      if (!file || !line) return;

      // Prevent path traversal outside the checked-out repo.
      const abs = path.resolve(repoDir, file);
      if (!abs.startsWith(path.resolve(repoDir) + path.sep)) return;

      try {
        const content = await fs.readFile(abs, "utf8");
        const lines = content.split("\n");
        const start = Math.max(0, line - 1 - WINDOW);
        const end = Math.min(lines.length, line - 1 + WINDOW + 1);
        finding.raw_snippet = lines
          .slice(start, end)
          .map((text, i) => `${start + i + 1}: ${text}`)
          .join("\n");
      } catch {
        // File not present (e.g. package.json-level findings) — leave null.
      }
    })
  );
}
