import express from "express";
import cors from "cors";
import { router } from "./api/routes";
import { config } from "./tools/util";
import { listProviders, hasUsableProvider } from "./llm";

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) =>
  res.json({ status: "ok", providers: listProviders() })
);

app.use("/api", router);

app.listen(config.port, () => {
  console.log(`Scanner-X backend listening on :${config.port}`);
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
