const express = require("express");
const session = require("express-session");
const lusca = require("lusca");
const app = express();
// ok: scanner-x.express-session-without-csrf
app.use(session({ secret: "s" }));
app.use(lusca.csrf());
