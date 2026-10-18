// Fixtures for scanner-x.yml: `semgrep --test --config ../scanner-x.yml .`
const express = require("express");
const session = require("express-session");
const swig = require("swig");
const needle = require("needle");
const axios = require("axios");

const app = express();
// ruleid: scanner-x.express-session-without-csrf
app.use(session({ secret: "s", resave: false }));

// ruleid: scanner-x.template-autoescape-disabled
swig.setDefaults({ autoescape: false });
// ok: scanner-x.template-autoescape-disabled
swig.setDefaults({ autoescape: true });

function allocations(userId, threshold) {
  // ruleid: scanner-x.nosql-where-injection
  return { $where: `this.userId == ${userId} && this.stocks > '${threshold}'` };
}
function allocations2(threshold) {
  // ruleid: scanner-x.nosql-where-injection
  return { $where: "this.stocks > " + threshold };
}
function safeQuery(userId, threshold) {
  // ok: scanner-x.nosql-where-injection
  return { userId, stocks: { $gt: threshold } };
}

app.get("/research", (req, res) => {
  const url = req.query.url + req.query.symbol;
  // ruleid: scanner-x.ssrf-user-controlled-url
  return needle.get(url, () => res.end());
});
app.get("/proxy", async (req, res) => {
  // ruleid: scanner-x.ssrf-user-controlled-url
  const r = await axios.get(`https://${req.body.host}/x`);
  res.send(r.data);
});
app.get("/quote", async (req, res) => {
  // ok: scanner-x.ssrf-user-controlled-url
  const r = await axios.get("https://api.example.com/quote?s=" + encodeURIComponent(req.query.s));
  res.send(r.data);
});
