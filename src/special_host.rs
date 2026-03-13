use http::{
    header::{CONTENT_DISPOSITION, CONTENT_TYPE},
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
};

use crate::{certificate::SPECIAL_HOST, state::AppState};

pub struct SpecialHostResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub notes: Vec<String>,
}

impl SpecialHostResponse {
    pub fn new(status: StatusCode, body: Vec<u8>, content_type: &'static str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        Self {
            status,
            headers,
            body,
            notes: Vec::new(),
        }
    }
}

pub fn is_special_host(host: &str) -> bool {
    host.split(':')
        .next()
        .map(|value| value.eq_ignore_ascii_case(SPECIAL_HOST))
        .unwrap_or(false)
}

pub fn respond(path: &str, method: &Method, state: &AppState, secure: bool) -> SpecialHostResponse {
    match (method, path) {
        (&Method::GET, "/") | (&Method::GET, "") => certificate_portal(state, secure),
        (&Method::GET, "/cert/root.pem") => {
            let mut response = SpecialHostResponse::new(
                StatusCode::OK,
                state.certificates.root_pem_bytes().to_vec(),
                "application/x-pem-file",
            );
            response.headers.insert(
                CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"sniper-root-ca.pem\""),
            );
            response
        }
        (&Method::GET, "/cert/root.der") => {
            let mut response = SpecialHostResponse::new(
                StatusCode::OK,
                state.certificates.root_der_bytes().to_vec(),
                "application/pkix-cert",
            );
            response.headers.insert(
                CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"sniper-root-ca.der\""),
            );
            response
        }
        (&Method::GET, "/favicon.ico") => {
            SpecialHostResponse::new(StatusCode::NO_CONTENT, Vec::new(), "image/x-icon")
        }
        _ => {
            let mut response = SpecialHostResponse::new(
                StatusCode::NOT_FOUND,
                b"Not found".to_vec(),
                "text/plain; charset=utf-8",
            );
            response
                .notes
                .push("Special host route not found.".to_string());
            response
        }
    }
}

fn certificate_portal(state: &AppState, secure: bool) -> SpecialHostResponse {
    let certificate = state.certificates.export();
    let scheme_name = if secure { "HTTPS" } else { "HTTP" };
    let html = format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sniper Certificate Portal</title>
    <style>
      :root {{
        --bg: #eff3f8;
        --panel: #ffffff;
        --line: #cfd8e3;
        --text: #1f2a37;
        --muted: #5b6673;
        --accent: #0b57d0;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        background: linear-gradient(180deg, #f6f8fb 0%, #e9eef6 100%);
        color: var(--text);
      }}
      .page {{
        max-width: 960px;
        margin: 0 auto;
        padding: 36px 20px 64px;
      }}
      .hero, .panel {{
        border: 1px solid var(--line);
        border-radius: 16px;
        background: var(--panel);
        box-shadow: 0 14px 34px rgba(15, 23, 42, 0.08);
      }}
      .hero {{
        padding: 28px;
        margin-bottom: 18px;
      }}
      .eyebrow {{
        margin: 0 0 8px;
        font-size: 0.76rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--muted);
      }}
      h1 {{ margin: 0 0 10px; font-size: 2rem; }}
      p {{ line-height: 1.6; }}
      .grid {{
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 18px;
      }}
      .panel {{
        padding: 22px;
      }}
      .actions {{
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin-top: 18px;
      }}
      .button {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-width: 170px;
        padding: 12px 16px;
        border-radius: 10px;
        text-decoration: none;
        font-weight: 700;
      }}
      .button.primary {{
        background: var(--accent);
        color: white;
      }}
      .button.secondary {{
        border: 1px solid var(--line);
        color: var(--text);
      }}
      dl {{
        margin: 0;
        display: grid;
        grid-template-columns: 180px 1fr;
        gap: 8px 14px;
      }}
      dt {{
        color: var(--muted);
        font-weight: 600;
      }}
      dd {{
        margin: 0;
        word-break: break-word;
        font-family: "JetBrains Mono", "SF Mono", monospace;
      }}
      code {{
        padding: 2px 6px;
        border-radius: 6px;
        background: #eef3fb;
        font-family: "JetBrains Mono", "SF Mono", monospace;
      }}
      ol {{
        margin: 0;
        padding-left: 18px;
        line-height: 1.7;
      }}
      @media (max-width: 820px) {{
        .grid {{
          grid-template-columns: 1fr;
        }}
        dl {{
          grid-template-columns: 1fr;
        }}
      }}
    </style>
  </head>
  <body>
    <div class="page">
      <section class="hero">
        <p class="eyebrow">Sniper Certificate Portal</p>
        <h1>Install the Sniper Root CA</h1>
        <p>
          You reached this page through the special <code>{}</code> host. Download the root certificate,
          trust it in your browser or operating system, and then revisit proxied HTTPS traffic.
        </p>
        <div class="actions">
          <a class="button primary" href="/cert/root.pem">Download PEM</a>
          <a class="button secondary" href="/cert/root.der">Download DER</a>
        </div>
      </section>

      <section class="grid">
        <article class="panel">
          <p class="eyebrow">Certificate</p>
          <dl>
            <dt>Common name</dt>
            <dd>{}</dd>
            <dt>Valid until</dt>
            <dd>{}</dd>
            <dt>PEM path</dt>
            <dd>{}</dd>
            <dt>DER path</dt>
            <dd>{}</dd>
          </dl>
        </article>

        <article class="panel">
          <p class="eyebrow">Use it</p>
          <ol>
            <li>Download the root CA in PEM or DER format.</li>
            <li>Import it as a trusted root certificate.</li>
            <li>Configure your client to use the Sniper proxy at <code>{}</code>.</li>
            <li>Re-open <code>https://{}</code> to confirm the CA is installed.</li>
          </ol>
          <p>
            If your browser warns on <code>https://{}</code> before the CA is trusted, that is expected.
            You can continue once to fetch the certificate or use <code>{}</code> from the same proxied client.
          </p>
        </article>
      </section>
    </div>
  </body>
</html>"#,
        scheme_name,
        escape_html(&certificate.common_name),
        escape_html(&certificate.expires_at.to_rfc3339()),
        escape_html(&certificate.pem_path),
        escape_html(&certificate.der_path),
        escape_html(&state.config.proxy_addr.to_string()),
        SPECIAL_HOST,
        SPECIAL_HOST,
        escape_html(&certificate.special_host_http),
    );

    let mut response = SpecialHostResponse::new(
        StatusCode::OK,
        html.into_bytes(),
        "text/html; charset=utf-8",
    );
    response.headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    response
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#039;")
}
