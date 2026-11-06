const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
test('TCP JavaScript is explicitly served and referenced by the embedded UI', () => {
  const source = fs.readFileSync(path.join(root, 'src/api.rs'), 'utf8');
  assert.match(source, /\.route\("\/tcp-capture\.js", get\(tcp_capture_js\)\)/);
  assert.match(source, /async fn tcp_capture_js\(\) -> Response\s*\{\s*asset_response\(\s*"application\/javascript; charset=utf-8",\s*include_str!\("\.\.\/web\/tcp-capture\.js"\)/);
  const html = fs.readFileSync(path.join(root, 'web/index.html'), 'utf8');
  assert.match(html, /<script[^>]+src="\/tcp-capture\.js"/);
  assert.ok(fs.statSync(path.join(root, 'web/tcp-capture.js')).size > 0);
});
