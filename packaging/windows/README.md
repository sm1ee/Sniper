# Sniper on Windows

Requires Windows 10/11, the [Microsoft Visual C++ v14 Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist),
and the [Microsoft Edge WebView2 Evergreen Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/).
Install the redistributable matching the package architecture if Windows reports a missing `VCRUNTIME140.dll` or `VCRUNTIME140_1.dll`.
Install WebView2 if Sniper reports a WebView2 startup error. The headless server and CLI do not need WebView2.

Extract the entire ZIP into a folder, then double-click `sniper-desktop.exe`.
The portable package includes `sniper.exe` (headless server) and `sniper-cli.exe` (automation CLI).
Sniper stores sessions and its CA in `%USERPROFILE%\.sniper`; if `HOME` is set, it uses `HOME\.sniper` instead.
Set `SNIPER_DATA_DIR` to choose a different data directory. All three executables use the same location.
Only one server or desktop app can use a data directory at a time.

## Capture HTTPS traffic

1. Open Sniper and configure your test browser to use HTTP/HTTPS proxy `127.0.0.1:8080`.
2. Visit `http://sniper` through that proxy and download the DER root certificate.
3. Open the certificate, choose **Install Certificate**, **Current User**, then **Place all certificates in the following store** and **Trusted Root Certification Authorities**.
4. Restart the test browser and visit your test target. Firefox may require importing the CA in its own certificate settings.

Sniper does not change the system proxy or install the CA automatically.
To remove trust later, use `certmgr.msc` and remove the Sniper CA from the current user's trusted roots.

## CLI and headless mode

Open PowerShell in the extracted folder. While the desktop is running:

```powershell
.\sniper-cli.exe session list
.\sniper-cli.exe --output compact capture http list --limit 10
```

For an isolated headless instance:

```powershell
$env:SNIPER_DATA_DIR = Join-Path $env:TEMP 'sniper-test'
$env:SNIPER_UI_ADDR = '127.0.0.1:18899'
$env:SNIPER_PROXY_ADDR = '127.0.0.1:18890'
.\sniper.exe
```

Open `http://127.0.0.1:18899`. Press Ctrl+C in the server console to save and exit.
Use the same `SNIPER_DATA_DIR` in a second terminal for CLI discovery, or pass `--api http://127.0.0.1:18899`.
You can add the extracted folder to your user PATH manually to use `sniper-cli` from other directories.

## Updates

Windows updates are manual. The Update button opens the releases page.
Close Sniper, extract the new ZIP into a new folder, and run its `sniper-desktop.exe`.
Your existing data stays in the user data directory. The macOS DMG installer is never used on Windows.

## Build from source

Install Rust with the MSVC toolchain, Visual Studio Build Tools with **Desktop development with C++** and a Windows SDK, and WebView2 Runtime.
Run from the repository root:

```powershell
cargo build --locked --release --bins
cargo test --locked --release
python tests/runtime_smoke.py
powershell -NoProfile -ExecutionPolicy Bypass -File packaging/windows/make-zip.ps1
```

The packaging script creates `dist/Sniper-<version>-windows-x64.zip` and a SHA-256 checksum.
For ARM64, install the `aarch64-pc-windows-msvc` Rust target and the matching MSVC build tools, then pass `-Target aarch64-pc-windows-msvc`.
ARM64 requires separate device validation; the initial Windows validation targets x64.

To package already tested native release binaries without rebuilding, pass
`-SkipBuild -BinaryDirectory target/release`. The script checks each executable's CPU architecture.
The smoke test requires Python 3.9+ and uses only a disposable local upstream and temporary data directory.
