const http = require("http");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "csp");
const port = Number(process.env.FIXTURE_PORT || 4175);
const server = http.createServer((request, response) => {
  const route = request.url === "/unsafe-inline" ? "unsafe-inline" : "no-csp";
  const file = path.join(root, route, "index.html");
  fs.readFile(file, (error, body) => {
    if (error) {
      response.writeHead(404).end("Not found");
      return;
    }
    response.writeHead(200, { "Content-Type": "text/html" });
    response.end(body);
  });
});

server.listen(port, () => {
  console.log(`CSP fixtures listening on http://127.0.0.1:${port}/no-csp and /unsafe-inline`);
});
