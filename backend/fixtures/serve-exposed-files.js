const http = require("http");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "exposed-files");
const port = Number(process.env.FIXTURE_PORT || 4174);
// The home page also exercises the header check: a version-revealing Server header (fix
// snippets should target nginx), a session cookie without flags, and CORS that trusts any
// origin with credentials.
function homeHeaders(request) {
  const headers = {
    Server: "nginx/1.18.0",
    "Set-Cookie": "sessionid=fixture123; Path=/",
  };
  if (request.headers.origin) {
    headers["Access-Control-Allow-Origin"] = request.headers.origin;
    headers["Access-Control-Allow-Credentials"] = "true";
  }
  return headers;
}

const TYPES = { ".html": "text/html", ".json": "application/json", ".map": "application/json", ".js": "text/javascript" };

const server = http.createServer((request, response) => {
  const pathname = new URL(request.url, "http://fixture").pathname;
  const relative = pathname === "/" ? "index.html" : decodeURIComponent(pathname.slice(1));
  const file = path.resolve(root, relative);
  if (!file.startsWith(`${root}${path.sep}`)) {
    response.writeHead(404).end();
    return;
  }
  fs.readFile(file, (error, body) => {
    if (error) {
      response.writeHead(404).end("Not found");
      return;
    }
    response.writeHead(200, {
      "Content-Type": TYPES[path.extname(file)] || "text/plain",
      ...(relative === "index.html" ? homeHeaders(request) : {}),
    });
    response.end(body);
  });
});

server.listen(port, () => {
  console.log(`Exposed-files fixture listening on http://127.0.0.1:${port}`);
});
