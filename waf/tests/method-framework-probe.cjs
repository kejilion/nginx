// Exercise the real method-override middleware, with the request received by
// the fixture upstream. No methods are reimplemented here and no socket opens.
const middleware = require(process.argv[2]);
const input = JSON.parse(process.argv[3]);
const headers = {};
const response = {
  getHeader: (name) => headers[name.toLowerCase()],
  setHeader: (name, value) => { headers[name.toLowerCase()] = value; },
};
const request = { method: input.method, headers: input.headers, url: input.path };
middleware(input.header)(request, response, () => {
  process.stdout.write(JSON.stringify({ original: request.originalMethod, effective: request.method }));
});
