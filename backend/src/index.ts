import express from "express";
import cors from "cors";
import { rateLimit } from "express-rate-limit";
import { router } from "./api/routes";
import { config } from "./tools/util";
import { allowPrivateTargets } from "./tools/netGuard";
import { describeGitCredentials, loadGitCredentials } from "./tools/gitAuth";
import { listProviders, hasUsableProvider } from "./llm";

const app = express();
const trustProxy = process.env.TRUST_PROXY?.trim();
if (trustProxy) {
  app.set("trust proxy", /^\d+$/.test(trustProxy) ? Number(trustProxy) : trustProxy);
}
const corsOrigins = new Set(
  (process.env.CORS_ORIGINS ?? "http://localhost:5173,http://127.0.0.1:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);

app.use(
  cors({
    origin: (origin, callback) => callback(null, !origin || corsOrigins.has(origin)),
  })
);
app.use(
  "/api/scan",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) =>
      res.status(429).json({ error: "Too many scan requests. Try again later." }),
  })
);
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) =>
  res.json({ status: "ok", providers: listProviders() })
);

app.use("/api", router);

app.listen(config.port, () => {
  console.log(`Scanner-X backend listening on :${config.port}`);
  if (allowPrivateTargets()) {
    console.warn(
      "WARNING: ALLOW_PRIVATE_TARGETS is on. Scans may reach localhost and internal networks; never enable this on a public deployment."
    );
  }
  const gitCreds = describeGitCredentials();
  if (gitCreds.length) {
    console.log(`Private repo access configured for: ${gitCreds.join("; ")}`);
    if (loadGitCredentials().some((c) => c.owners.length === 0)) {
      console.warn(
        "WARNING: a git token has no owner restriction. Anyone who can reach this API can scan every repo that token can read; set *_OWNERS or \"owners\" in GIT_CREDENTIALS."
      );
    }
  }
  const usable = listProviders().filter((p) => p.available);
  if (hasUsableProvider()) {
    console.log(
      `LLM triage enabled via: ${usable
        .map((p) => `${p.label} (${p.model})${p.isDefault ? " [default]" : ""}`)
        .join(", ")}`
    );
  } else {
    console.log(
      "LLM triage disabled (no usable provider) — running deterministic-only mode."
    );
  }
});
