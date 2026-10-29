"""Compare served UI bytes with this checkout using an isolated headless binary.

Run: python3 tests/embedded_assets_smoke.py [binary directory]
This is an HTTP/source-identity check, not a browser, DOM or visual test. It sends
no proxy traffic, launches no browser and never reads a real session directory.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def eventually(operation, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = operation()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for isolated asset fixture")


def main():
    binaries = Path(sys.argv[1] if len(sys.argv) > 1 else "target/release").resolve()
    source = Path(__file__).resolve().parents[1] / "web"
    assets = [
        ("/", "index.html", "text/html"),
        ("/styles.css", "styles.css", "text/css"),
        ("/app.js", "app.js", "application/javascript"),
        ("/service-map.js", "service-map.js", "application/javascript"),
        ("/recon.js", "recon.js", "application/javascript"),
        ("/templates.js", "templates.js", "application/javascript"),
        ("/fuzzer-workflow.js", "fuzzer-workflow.js", "application/javascript"),
        ("/product-icons.js", "product-icons.js", "application/javascript"),
        ("/codemirror.js", "codemirror.bundle.js", "application/javascript"),
    ]
    expected = {name: (source / name).read_bytes() for _, name, _ in assets}
    suffix = ".exe" if os.name == "nt" else ""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    env = {key: value for key, value in os.environ.items()
           if not key.lower().endswith("_proxy")}
    env.pop("SNIPER_API_ADDR", None)
    process = None
    with tempfile.TemporaryDirectory(prefix="sniper-assets-") as temporary:
        data = Path(temporary)
        env.update(SNIPER_DATA_DIR=str(data), SNIPER_UI_ADDR="127.0.0.1:0",
                   SNIPER_PROXY_ADDR="127.0.0.1:0", SNIPER_INSTALL_AGENT_SKILLS="0",
                   SNIPER_INSTALL_CLI_PATH="0", RUST_LOG="off")
        try:
            process = subprocess.Popen([str(binaries / ("sniper" + suffix))], env=env,
                                       cwd=data, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, creationflags=flags)

            def ready():
                assert process.poll() is None, "Runtime exited before becoming ready"
                try:
                    value = json.loads((data / "runtime-state.json").read_text())
                    return value if value["pid"] == process.pid else None
                except (OSError, ValueError):
                    return None

            runtime = eventually(ready)
            host, port = runtime["ui_addr"].rsplit(":", 1)
            assert host == "127.0.0.1"

            def read(path):
                connection = http.client.HTTPConnection(host, int(port), timeout=10)
                try:
                    connection.request("GET", path, headers={"Accept-Encoding": "identity"})
                    response = connection.getresponse()
                    body = response.read()
                    assert response.status == 200, (path, response.status)
                    return dict(response.getheaders()), body
                finally:
                    connection.close()

            def api_ready():
                try:
                    headers, body = read("/api/transactions")
                    assert json.loads(body) == [], "Temporary fixture must have no captured traffic"
                    return True
                except (ConnectionError, OSError):
                    return False

            eventually(api_ready)
            for path, name, content_type in assets:
                headers, body = read(path)
                headers = {key.lower(): value for key, value in headers.items()}
                assert headers.get("content-type", "").startswith(content_type), name
                assert headers.get("cache-control") == "no-cache, no-store, must-revalidate", name
                assert body == expected[name], f"Embedded asset differs from checkout: {name}"
                print(json.dumps({"asset": name, "path": path, "bytes": len(body),
                                  "sha256": hashlib.sha256(body).hexdigest()}), flush=True)
            assert api_ready()
            for name, body in expected.items():
                assert (source / name).read_bytes() == body, f"Source changed during smoke: {name}"
            print("PASS: 9 served UI assets exactly match checkout; zero proxy captures; no browser or DOM execution", flush=True)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
