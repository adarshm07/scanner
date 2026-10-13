const http = require("http");
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "exposed-files");
const port = Number(process.env.FIXTURE_PORT || 4174);
const server = http.createServer((request, response) => {
  const relative = request.url === "/" ? "index.html" : request.url.slice(1);
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
      "Content-Type": file.endsWith(".html") ? "text/html" : "text/plain",
    });
    response.end(body);
  });
});

server.listen(port, () => {
  console.log(`Exposed-files fixture listening on http://127.0.0.1:${port}`);
});
