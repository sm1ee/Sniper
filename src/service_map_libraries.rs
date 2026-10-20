//! Front-end technologies retained responses declare: frameworks, CMSs, UI kits
//! and libraries, with a version when one is named.
//!
//! Response headers name few products and rarely a version: `X-Powered-By:
//! Next.js` carries none. Responses say more in three places, all read here
//! without running anything:
//! - a script's license banner (`/*! jQuery v3.7.1`) or runtime value
//!   (`window.next={version:"14.2.3"}`, React DOM's renderer registration);
//! - a page's markup: attributes frameworks render (`ng-version="17.1.0"`,
//!   `data-v-1a2b3c4d`), their root ids (`__nuxt`, `___gatsby`) and its
//!   `<meta name="generator">`;
//! - asset URLs: a CDN's `package@version` path, a versioned file name, or the
//!   directory a framework builds into (`/_next/static/`, `/wp-content/`).
//!
//! Wappalyzer's catalogue was the checklist of products and of the signals each
//! leaves; every rule here is written for this table, not taken from its data.
//! Only these anchors count: a bundle holds other libraries' `version:"…"`
//! literals too.
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::LazyLock,
};

use regex::{Regex, RegexSet};
use serde::Deserialize;
use uuid::Uuid;

use crate::{model::BodyEncoding, service_map::ServiceMapRow, session::BodyLocator};

/// Retained rows read from disk per map; the rest are read on later maps.
pub const MAX_READS: usize = 256;
/// Bytes copied or read per map, resident and retained together.
pub const MAX_BYTES_PER_MAP: usize = 32 * 1024 * 1024;
/// A serialized row larger than this is not read at all. Single-page apps
/// ship bundles of several MiB; at 2 MiB a crawl left three sites'
/// frameworks unread.
pub const MAX_ROW_BYTES: usize = 8 * 1024 * 1024;
/// Script and stylesheet URLs read from one page.
const MAX_PAGE_URLS: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub product_id: String,
    pub name: String,
    pub category: &'static str,
    /// None when the signal names the product but not its version.
    pub version: Option<String>,
    /// Empty for a front-end signal; `service_map_servers::SIGNALS` for one the
    /// responding origin's own headers, cookies or body gave.
    pub signal: &'static str,
}

/// What a row's body can declare: a script's technologies, a page's, or what
/// an error, a root or an API document response says about its servers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Script,
    Page,
    Data,
}

pub(crate) fn kind(row: &ServiceMapRow) -> Option<Kind> {
    let mime = row.content_type.as_deref()?;
    if mime.contains("javascript") || mime.contains("ecmascript") {
        Some(Kind::Script)
    } else if mime.contains("html") {
        Some(Kind::Page)
    } else if (mime.contains("json") || mime.contains("xml") || mime.starts_with("text/"))
        && (row.status.is_some_and(|status| status >= 400)
            || row.sent_from_replay
            || diagnostic_path(&row.path))
    {
        // Only these are read: an API's every success would spend the budget.
        // A request a tester sent from Replay is few and chosen, so its answer
        // is read whatever its status.
        Some(Kind::Data)
    } else {
        None
    }
}

/// A path whose own answer says what runs there: the root, Spring's Actuator,
/// an API document, and the management and debug endpoints a tester or a
/// scanner asks for (`/.git/config`, `/.env`, Go's `/debug/vars`, Jolokia,
/// Apache's `server-status`, Prometheus's `/metrics`).
fn diagnostic_path(path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path == "/"
        || [
            "/actuator",
            "/jolokia",
            "/debug/pprof",
            "/manage",
            "/management",
            "/h2-console",
        ]
        .iter()
        .any(|prefix| path.starts_with(prefix))
        || ["/api-docs", "openapi.json", "swagger.json"]
            .iter()
            .any(|end| path.ends_with(end))
        || [
            "/.git/config",
            "/.env",
            "/debug/vars",
            "/server-status",
            "/server-info",
            "/nginx_status",
            "/stub_status",
            "/metrics",
            "/prometheus",
            "/health",
            "/healthz",
            "/info",
            "/env",
            "/version",
            "/graphiql",
            "/playground",
        ]
        .contains(&path)
}

pub const META_FRAMEWORK: &str = "meta_framework";
pub const CMS: &str = "cms";
pub const FRAMEWORK: &str = "framework";
pub const UI: &str = "ui";
pub const LIBRARY: &str = "library";
pub const ANALYTICS: &str = "analytics";
/// Categories in the order a card presents them: what the site is built with
/// first, what it merely loads last.
pub const CATEGORIES: [&str; 6] = [META_FRAMEWORK, CMS, FRAMEWORK, UI, LIBRARY, ANALYTICS];

const PRODUCTS: &[(&str, &str, &str)] = &[
    ("next_js", "Next.js", META_FRAMEWORK),
    ("nuxt", "Nuxt", META_FRAMEWORK),
    ("sveltekit", "SvelteKit", META_FRAMEWORK),
    ("remix", "Remix", META_FRAMEWORK),
    ("gatsby", "Gatsby", META_FRAMEWORK),
    ("astro", "Astro", META_FRAMEWORK),
    ("wordpress", "WordPress", CMS),
    ("drupal", "Drupal", CMS),
    ("joomla", "Joomla", CMS),
    ("magento", "Magento", CMS),
    ("shopify", "Shopify", CMS),
    ("wix", "Wix", CMS),
    ("squarespace", "Squarespace", CMS),
    ("adobe_experience_manager", "Adobe Experience Manager", CMS),
    ("framer", "Framer", CMS),
    ("magnolia", "Magnolia", CMS),
    ("react", "React", FRAMEWORK),
    ("vue", "Vue.js", FRAMEWORK),
    ("angular", "Angular", FRAMEWORK),
    ("angularjs", "AngularJS", FRAMEWORK),
    ("svelte", "Svelte", FRAMEWORK),
    ("ember", "Ember.js", FRAMEWORK),
    ("preact", "Preact", FRAMEWORK),
    ("lit", "Lit", FRAMEWORK),
    ("qwik", "Qwik", FRAMEWORK),
    ("alpine_js", "Alpine.js", FRAMEWORK),
    ("htmx", "htmx", FRAMEWORK),
    ("hotwire_turbo", "Turbo", FRAMEWORK),
    ("livewire", "Livewire", FRAMEWORK),
    ("backbone", "Backbone.js", FRAMEWORK),
    ("knockout", "Knockout", FRAMEWORK),
    ("bootstrap", "Bootstrap", UI),
    ("vuetify", "Vuetify", UI),
    ("element_plus", "Element Plus", UI),
    ("element_ui", "Element UI", UI),
    ("quasar", "Quasar", UI),
    ("font_awesome", "Font Awesome", UI),
    ("jquery", "jQuery", LIBRARY),
    ("jquery_ui", "jQuery UI", LIBRARY),
    ("jquery_migrate", "jQuery Migrate", LIBRARY),
    ("lodash", "Lodash", LIBRARY),
    ("underscore", "Underscore.js", LIBRARY),
    ("moment", "Moment.js", LIBRARY),
    ("dayjs", "Day.js", LIBRARY),
    ("core_js", "core-js", LIBRARY),
    ("axios", "Axios", LIBRARY),
    ("socket_io", "Socket.IO", LIBRARY),
    ("dompurify", "DOMPurify", LIBRARY),
    ("chart_js", "Chart.js", LIBRARY),
    ("d3", "D3", LIBRARY),
    ("three_js", "three.js", LIBRARY),
    ("leaflet", "Leaflet", LIBRARY),
    ("highcharts", "Highcharts", LIBRARY),
    ("echarts", "ECharts", LIBRARY),
    ("gsap", "GSAP", LIBRARY),
    ("swiper", "Swiper", LIBRARY),
    ("video_js", "Video.js", LIBRARY),
    ("hls_js", "hls.js", LIBRARY),
    ("select2", "Select2", LIBRARY),
    ("popper", "Popper", LIBRARY),
    ("handlebars", "Handlebars", LIBRARY),
    ("modernizr", "Modernizr", LIBRARY),
    ("zepto", "Zepto", LIBRARY),
    ("prototype", "Prototype", LIBRARY),
    ("mootools", "MooTools", LIBRARY),
    ("pdf_js", "PDF.js", LIBRARY),
    ("tinymce", "TinyMCE", LIBRARY),
    ("ckeditor", "CKEditor", LIBRARY),
    ("quill", "Quill", LIBRARY),
    ("sweetalert2", "SweetAlert2", LIBRARY),
    ("hammer_js", "Hammer.js", LIBRARY),
    ("sentry", "Sentry", LIBRARY),
    ("slick", "Slick", LIBRARY),
    ("aos", "AOS", LIBRARY),
    ("html5shiv", "html5shiv", LIBRARY),
    ("respond_js", "Respond.js", LIBRARY),
    ("fullpage_js", "fullPage.js", LIBRARY),
    ("scrollmagic", "ScrollMagic", LIBRARY),
    ("mcustomscrollbar", "malihu custom scrollbar", LIBRARY),
    ("netfunnel", "NetFUNNEL", LIBRARY),
    ("onetrust", "OneTrust", LIBRARY),
    ("google_translate", "Google Translate", LIBRARY),
    ("recaptcha", "reCAPTCHA", LIBRARY),
    ("ie9_js", "IE9.js", LIBRARY),
    ("jquery_blockui", "BlockUI", LIBRARY),
    ("jquery_cookie", "jquery-cookie", LIBRARY),
    ("simplemodal", "SimpleModal", LIBRARY),
    ("bxslider", "bxSlider", LIBRARY),
    ("jquery_easing", "jQuery Easing", LIBRARY),
    ("owl_carousel", "Owl Carousel", LIBRARY),
    ("jquery_form", "jQuery Form", LIBRARY),
    ("naver_login", "NAVER Login", LIBRARY),
    ("nprotect", "nProtect Online Security", LIBRARY),
    ("highlight_js", "highlight.js", LIBRARY),
    ("requirejs", "RequireJS", LIBRARY),
    ("fontfaceobserver", "Font Face Observer", LIBRARY),
    ("webcomponentsjs", "Web Components polyfills", LIBRARY),
    ("web_animations_js", "Web Animations polyfill", LIBRARY),
    ("polyfill_io", "Polyfill.io", LIBRARY),
    ("firebase", "Firebase", LIBRARY),
    ("google_maps", "Google Maps", LIBRARY),
    ("naver_maps", "NAVER Maps", LIBRARY),
    ("google_api_client", "Google API Client", LIBRARY),
    ("hcaptcha", "hCaptcha", LIBRARY),
    ("cloudflare_turnstile", "Cloudflare Turnstile", LIBRARY),
    ("stripe_js", "Stripe.js", LIBRARY),
    ("paypal_sdk", "PayPal JS SDK", LIBRARY),
    ("portone", "PortOne", LIBRARY),
    ("toss_payments", "Toss Payments", LIBRARY),
    ("kg_inicis", "KG Inicis", LIBRARY),
    ("nicepay", "NICEPAY", LIBRARY),
    ("channel_talk", "Channel Talk", LIBRARY),
    ("intercom", "Intercom", LIBRARY),
    ("zendesk_widget", "Zendesk Widget", LIBRARY),
    ("cookiebot", "Cookiebot", LIBRARY),
    ("didomi", "Didomi", LIBRARY),
    ("trustarc", "TrustArc", LIBRARY),
    ("usercentrics", "Usercentrics", LIBRARY),
    ("sourcepoint", "Sourcepoint", LIBRARY),
    ("quantcast_choice", "Quantcast Choice", LIBRARY),
    ("google_tag_manager", "Google Tag Manager", ANALYTICS),
    ("google_analytics", "Google Analytics", ANALYTICS),
    ("naver_analytics", "NAVER Analytics", ANALYTICS),
    ("cloudflare_insights", "Cloudflare Web Analytics", ANALYTICS),
    ("google_ad_manager", "Google Ad Manager", ANALYTICS),
    ("google_adsense", "Google AdSense", ANALYTICS),
    ("google_ads", "Google Ads", ANALYTICS),
    ("marketo", "Marketo", ANALYTICS),
    ("tealium", "Tealium iQ", ANALYTICS),
    ("adobe_launch", "Adobe Launch", ANALYTICS),
    ("amplitude", "Amplitude", ANALYTICS),
    ("mixpanel", "Mixpanel", ANALYTICS),
    ("segment", "Segment", ANALYTICS),
    ("hotjar", "Hotjar", ANALYTICS),
    ("microsoft_clarity", "Microsoft Clarity", ANALYTICS),
    ("plausible", "Plausible", ANALYTICS),
    ("matomo", "Matomo", ANALYTICS),
    ("chartbeat", "Chartbeat", ANALYTICS),
    ("akamai_mpulse", "Akamai mPulse", ANALYTICS),
    ("new_relic", "New Relic Browser", ANALYTICS),
    ("datadog_rum", "Datadog RUM", ANALYTICS),
    ("hubspot", "HubSpot", ANALYTICS),
    ("meta_pixel", "Meta Pixel", ANALYTICS),
    ("tiktok_pixel", "TikTok Pixel", ANALYTICS),
    ("linkedin_insight", "LinkedIn Insight Tag", ANALYTICS),
    ("x_pixel", "X Pixel", ANALYTICS),
    ("microsoft_uet", "Microsoft Advertising UET", ANALYTICS),
    ("criteo", "Criteo", ANALYTICS),
    ("taboola", "Taboola", ANALYTICS),
    ("outbrain", "Outbrain", ANALYTICS),
    ("yandex_metrica", "Yandex Metrica", ANALYTICS),
    ("baidu_tongji", "Baidu Tongji", ANALYTICS),
    ("monetate", "Monetate", ANALYTICS),
    ("optimizely", "Optimizely", ANALYTICS),
    ("vwo", "VWO", ANALYTICS),
    ("acecounter", "AceCounter", ANALYTICS),
    ("beusable", "Beusable", ANALYTICS),
    ("dable", "Dable", ANALYTICS),
    ("the_trade_desk", "The Trade Desk", ANALYTICS),
    ("pubmatic", "PubMatic", ANALYTICS),
    ("tapad", "Tapad", ANALYTICS),
    ("sixsense", "6sense", ANALYTICS),
    ("snap_pixel", "Snap Pixel", ANALYTICS),
    ("pinterest_tag", "Pinterest Tag", ANALYTICS),
    ("klaviyo", "Klaviyo", ANALYTICS),
    ("clearbit", "Clearbit", ANALYTICS),
    ("dynatrace_rum", "Dynatrace RUM", ANALYTICS),
    ("appdynamics_browser", "AppDynamics Browser RUM", ANALYTICS),
    ("yahoo_japan_ads", "Yahoo! JAPAN Ads", ANALYTICS),
    ("ethicalads", "EthicalAds", ANALYTICS),
    ("adobe_advertising", "Adobe Advertising", ANALYTICS),
    ("exelbid", "Exelbid", ANALYTICS),
    ("magnite", "Magnite", ANALYTICS),
    ("liveramp", "LiveRamp", ANALYTICS),
    ("sovrn", "Sovrn", ANALYTICS),
    ("deepintent", "DeepIntent", ANALYTICS),
    ("thirty_three_across", "33Across", ANALYTICS),
    ("adkernel", "AdKernel", ANALYTICS),
    ("stackadapt", "StackAdapt", ANALYTICS),
    ("semasio", "Semasio", ANALYTICS),
    ("conversant", "Conversant", ANALYTICS),
];

// Each rule names a product in PRODUCTS. `§` is the version: a digit, then
// letters, digits, `.`, `-` or `+`. A rule without one names the product only.
const SCRIPT_SIGNATURES: &[(&str, &str)] = &[
    ("react", r#"version:"§",rendererPackageName:"react-dom""#),
    ("react", r"@license React v§"),
    ("react", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"),
    (
        "vue",
        r"@vue/(?:runtime-dom|runtime-core|shared|reactivity|compiler-core|compiler-dom) v§",
    ),
    ("vue", r"Vue\.js v§"),
    ("vue", r"(?m)^\s*\*\s*vue v§"),
    ("vue", r"__v_isRef"),
    ("nuxt", r#"get nuxt\(\)\{return"§""#),
    ("nuxt", r"__NUXT__"),
    ("angular", r"@license Angular v§"),
    ("angular", r"ɵcmp"),
    ("angularjs", r"@license AngularJS v§"),
    (
        "angularjs",
        r#"\{full:"§",major:[0-9]+,minor:[0-9]+,dot:[0-9]+"#,
    ),
    ("svelte", r#"__svelte\b[^;]{0,80}?\.add\(["']§["']\)"#),
    ("svelte", r"window\.__svelte\b"),
    (
        "ember",
        r"Ember - JavaScript Application Framework[\s\S]{0,400}?@version\s+§",
    ),
    ("ember", r"Ember - JavaScript Application Framework"),
    (
        "lit",
        r#"lit(?:Html|Element)Versions[^;]{0,60}?\.push\(["']§["']\)"#,
    ),
    ("alpine_js", r#"version:"§",flushAndStopDeferringMutations"#),
    ("htmx", r#"indicatorClass:\s*["']htmx-indicator["']"#),
    ("backbone", r"Backbone\.js §"),
    ("knockout", r"Knockout JavaScript library v§"),
    ("bootstrap", r"Bootstrap v§ \(https?://getbootstrap\.com"),
    ("vuetify", r"Vuetify v§"),
    ("element_plus", r"Element Plus v§"),
    ("quasar", r"Quasar Framework v§"),
    ("font_awesome", r"Font Awesome (?:Free|Pro) §"),
    // The minified banner and the full build's; a plugin saying it needs
    // "jQuery v1.7" is neither.
    ("jquery", r"/\*!\s*jQuery v§"),
    ("jquery", r"jQuery JavaScript Library v§"),
    ("jquery_ui", r"jQuery UI - v§"),
    ("jquery_migrate", r"jQuery Migrate v§"),
    (
        "lodash",
        r"Lodash <https://lodash\.com/>|Lodash lodash\.com/license",
    ),
    // Lodash's own banner names "Underscore.js 1.8.3"; Underscore's starts a
    // comment line.
    ("underscore", r"(?m)^\s*(?://|/?\*+!?)\s*Underscore\.js §"),
    ("moment", r"//! moment\.js\s*//! version : §"),
    ("core_js", r#"version:"§",mode:"(?:global|pure)""#),
    ("axios", r"Axios v§ Copyright"),
    ("socket_io", r"Socket\.IO v§"),
    ("dompurify", r"DOMPurify § \|"),
    ("chart_js", r"Chart\.js v§"),
    ("d3", r"https://d3js\.org v§"),
    ("three_js", r#"__THREE__\s*=\s*["']§["']"#),
    (
        "three_js",
        r"Multiple instances of Three\.js being imported",
    ),
    ("leaflet", r"Leaflet §, a JS library for interactive maps"),
    ("highcharts", r"Highcharts JS v§"),
    ("gsap", r"\* GSAP §"),
    ("swiper", r"\* Swiper §"),
    ("video_js", r"Video\.js § <"),
    ("select2", r"Select2 § \|"),
    ("popper", r"@popperjs/core v§"),
    ("handlebars", r"handlebars v§"),
    ("modernizr", r"modernizr § \(Custom Build\)"),
    ("zepto", r"Zepto v§"),
    ("prototype", r"Prototype JavaScript framework, version §"),
    ("mootools", r#"MooTools\s*=\s*\{\s*version\s*:\s*["']§"#),
    ("pdf_js", r#"pdfjsVersion\s*=\s*["']§"#),
    ("tinymce", r"TinyMCE version §"),
    ("ckeditor", r#"timestamp:"[A-Z0-9]{4}",version:"§"#),
    ("ckeditor", r"CKEDITOR_VERSION"),
    ("quill", r"Quill Editor v§"),
    ("sweetalert2", r"sweetalert2 v§"),
    ("hammer_js", r"Hammer\.JS - v§"),
    ("sentry", r"@sentry/(?:browser|react|vue|angular|nextjs) §"),
    ("highlight_js", r"(?i)highlight\.js v§"),
    ("requirejs", r"RequireJS §"),
];

const PAGE_SIGNATURES: &[(&str, &str)] = &[
    ("new_relic", r"window\.NREUM\|\|\(NREUM=\{\}\)"),
    // The settings an inline snippet leaves before its loader runs.
    ("chartbeat", r"\b_sf_async_config\b"),
    (
        "plausible",
        r"window\.plausible\s*=\s*window\.plausible\s*\|\|",
    ),
    ("angular", r#"\bng-version="§""#),
    (
        "angular",
        r"\b_ng(?:host|content)-[a-z0-9-]+|\bng-server-context=",
    ),
    (
        "angularjs",
        r"<[a-zA-Z][^>]*\s(?:data-)?ng-(?:app|controller)\b",
    ),
    (
        "next_js",
        r#"<script[^>]+id=["']__NEXT_DATA__["']|self\.__next_f\.push|/_next/static/"#,
    ),
    (
        "nuxt",
        r#"<div[^>]+id=["']__nuxt["']|window\.__NUXT__|/_nuxt/"#,
    ),
    ("react", r"\sdata-react(?:root|id)\b"),
    (
        "vue",
        r#"<[a-zA-Z][^>]*\sdata-v-[0-9a-f]{8}\b|\sdata-server-rendered=["']true["']"#,
    ),
    ("svelte", r#"\sclass=["'][^"']*\bsvelte-[a-z0-9]{5,8}\b"#),
    (
        "sveltekit",
        r"\sdata-sveltekit-[a-z-]+|__sveltekit_[a-z0-9]+|/_app/immutable/",
    ),
    ("gatsby", r#"<div[^>]+id=["']___gatsby["']"#),
    ("astro", r"<astro-island\b|/_astro/"),
    ("remix", r"__remixContext|__remixManifest"),
    ("qwik", r#"\sq:version=["']§["']"#),
    ("qwik", r"\sq:container="),
    (
        "ember",
        r#"\sclass=["'][^"']*\bember-view\b|<meta[^>]+name=["'][^"']*/config/environment["']"#,
    ),
    ("alpine_js", r"<[a-zA-Z][^>]*\sx-data(?:=|\s|>)"),
    (
        "htmx",
        r"<[a-zA-Z][^>]*\shx-(?:get|post|put|patch|delete|boost|target|swap|trigger)=",
    ),
    ("livewire", r"\swire:(?:model|click|submit|loading|id)\b"),
    ("hotwire_turbo", r"<turbo-frame\b|\sdata-turbo(?:-[a-z]+)?="),
    ("knockout", r#"<[a-zA-Z][^>]*\sdata-bind=["']"#),
    (
        "wordpress",
        r#"/wp-content/|/wp-includes/|<link[^>]+rel=["']https://api\.w\.org/["']"#,
    ),
    (
        "drupal",
        r"\sdata-drupal-[a-z-]+=|drupalSettings|Drupal\.settings|/sites/(?:default|all)/(?:files|modules|themes)/",
    ),
    ("joomla", r"/media/(?:jui|system/js)/"),
    (
        "magento",
        r"\sdata-mage-init=|Mage\.Cookies|/static/version[0-9]+/frontend/",
    ),
    ("shopify", r"cdn\.shopify\.com|\bShopify\.theme\b"),
    ("wix", r"static\.(?:wixstatic|parastorage)\.com"),
    (
        "squarespace",
        r"static1\.squarespace\.com|Static\.SQUARESPACE_CONTEXT",
    ),
    ("google_tag_manager", r"googletagmanager\.com/gtm\.js"),
    (
        "google_analytics",
        r"googletagmanager\.com/gtag/js|google-analytics\.com/(?:analytics|ga)\.js",
    ),
];

/// Directories and hosts a product serves its assets from.
const URL_MARKERS: &[(&str, &str)] = &[
    ("next_js", r"/_next/static/"),
    ("nuxt", r"/_nuxt/"),
    ("sveltekit", r"/_app/immutable/"),
    ("astro", r"/_astro/"),
    ("gatsby", r"/webpack-runtime-[0-9a-f]+\.js"),
    ("remix", r"/build/(?:_shared/|entry\.client-)"),
    ("wordpress", r"/wp-(?:content|includes)/"),
    (
        "drupal",
        r"/sites/(?:default|all)/(?:files|modules|themes)/|/core/misc/drupal(?:\.init)?\.js",
    ),
    ("joomla", r"/media/(?:jui|system/js)/"),
    ("magento", r"/static/version[0-9]+/frontend/"),
    ("shopify", r"cdn\.shopify\.com/|sdks\.shopifycdn\.com/"),
    ("wix", r"static\.(?:wixstatic|parastorage)\.com/"),
    ("squarespace", r"(?:static1|assets)\.squarespace\.com/"),
    ("livewire", r"/livewire(?:\.min)?\.js"),
    ("slick", r"(?i)/slick(?:\.min)?\.js(?:$|[?#])"),
    ("aos", r"(?i)/aos(?:\.min)?\.js(?:$|[?#])"),
    (
        "html5shiv",
        r"(?i)/html5shiv(?:-printshiv)?(?:\.min)?\.js|/trunk/html5\.js(?:$|[?#])",
    ),
    ("respond_js", r"(?i)/respond(?:\.min|\.src)?\.js(?:$|[?#])"),
    (
        "fullpage_js",
        r"(?i)/(?:jquery\.)?fullpage(?:\.min)?\.js(?:$|[?#])",
    ),
    ("scrollmagic", r"(?i)/scrollmagic(?:\.min)?\.js(?:$|[?#])"),
    (
        "mcustomscrollbar",
        r"(?i)/jquery\.mcustomscrollbar(?:\.concat)?(?:\.min)?\.js",
    ),
    // STCLab's NetFUNNEL waiting room, which Korean sites put before a sale
    // or a sign-up.
    ("netfunnel", r"(?i)/netfunnel(?:\.min)?\.js(?:$|[?#])"),
    ("naver_analytics", r"wcs\.naver\.net/wcslog\.js"),
    ("moment", r"(?i)/moment(?:\.min)?\.js(?:$|[?#])"),
    (
        "onetrust",
        r"(?i)cdn\.cookielaw\.org/|/scripttemplates/otsdkstub\.js",
    ),
    (
        "cloudflare_insights",
        r"static\.cloudflareinsights\.com/beacon\.min\.js",
    ),
    (
        "google_ad_manager",
        r"securepubads\.g\.doubleclick\.net/tag/js/gpt\.js",
    ),
    ("google_adsense", r"/pagead/js/adsbygoogle\.js"),
    (
        "google_ads",
        r"googleadservices\.com/pagead/conversion(?:_async)?\.js|googleads\.g\.doubleclick\.net/pagead/viewthroughconversion/",
    ),
    (
        "google_translate",
        r"translate\.google\.com/translate_a/element\.js",
    ),
    (
        "recaptcha",
        r"(?:www\.google\.com|www\.recaptcha\.net)/recaptcha/(?:api|enterprise)\.js",
    ),
    (
        "marketo",
        r"(?i)marketo\.com/js/forms2/|munchkin\.marketo\.net/",
    ),
    // AEM's client libraries and the Granite UI they build on.
    (
        "adobe_experience_manager",
        r"/etc\.clientlibs/|/libs/granite/|/etc/designs/",
    ),
    ("ie9_js", r"(?i)/ie(?:7|8|9)(?:\.min)?\.js(?:$|[?#])"),
    ("jquery_blockui", r"(?i)/jquery\.blockui(?:\.min)?\.js"),
    ("jquery_cookie", r"(?i)/jquery\.cookie(?:\.min)?\.js"),
    (
        "simplemodal",
        r"(?i)/jquery\.simplemodal(?:-§)?(?:\.min)?\.js",
    ),
    ("bxslider", r"(?i)/jquery\.bxslider(?:\.min)?\.js"),
    (
        "jquery_easing",
        r"(?i)/jquery\.easing(?:\.§)?(?:\.min)?\.js",
    ),
    ("owl_carousel", r"(?i)/owl\.carousel(?:\.min)?\.js"),
    ("jquery_form", r"(?i)/jquery\.form(?:\.min)?\.js"),
    (
        "naver_login",
        r"(?i)/naveridlogin_js_sdk_§\.js|static\.nid\.naver\.com/js/naveridlogin",
    ),
    // INCA Internet's nProtect, the keyboard and firewall plug-in Korean
    // banks load before a sign-in.
    (
        "nprotect",
        r"(?i)/nppfs-§\.js|/nppfs(?:\.min)?\.js|/nppfsstartup\.js",
    ),
    ("google_tag_manager", r"googletagmanager\.com/gtm\.js"),
    (
        "google_analytics",
        r"googletagmanager\.com/gtag/js|google-analytics\.com/(?:analytics|ga)\.js",
    ),
    // A library's own file without a version: the body names the version
    // when it is read, a stylesheet only ever by its URL.
    ("jquery", r"(?i)/jquery(?:\.slim)?(?:\.min)?\.js(?:$|[?#])"),
    (
        "jquery_ui",
        r"(?i)/jquery-ui(?:\.min)?\.(?:js|css)(?:$|[?#])",
    ),
    (
        "bootstrap",
        r"(?i)/bootstrap(?:\.bundle)?\.min\.(?:js|css)(?:$|[?#])|/bootstrap\.css(?:$|[?#])",
    ),
    (
        "swiper",
        r"(?i)/swiper-bundle(?:\.min)?\.(?:js|css)(?:$|[?#])|/swiper\.min\.(?:js|css)(?:$|[?#])",
    ),
    (
        "font_awesome",
        r"(?i)/font-?awesome(?:\.min)?\.css(?:$|[?#])|//kit\.fontawesome\.com/",
    ),
    (
        "highlight_js",
        r"(?i)/highlight\.(?:pack|min)\.js(?:$|[?#])",
    ),
    ("requirejs", r"(?i)/require(?:\.min)?\.js(?:$|[?#])"),
    (
        "fontfaceobserver",
        r"(?i)/fontfaceobserver(?:\.standalone)?(?:\.min)?\.js(?:$|[?#])",
    ),
    (
        "webcomponentsjs",
        r"(?i)/webcomponents-[a-z-]+(?:\.min)?\.js(?:$|[?#])",
    ),
    (
        "web_animations_js",
        r"(?i)/web-animations(?:-next)?(?:-lite)?(?:\.min)?\.js(?:$|[?#])",
    ),
    // The domain a new owner used to serve malware from in 2024.
    ("polyfill_io", r"(?i)//(?:cdn\.)?polyfill\.io/"),
    ("firebase", r"//www\.gstatic\.com/firebasejs/"),
    ("google_maps", r"//maps\.googleapis\.com/maps/api/js"),
    ("naver_maps", r"//(?:o|open)api\.map\.naver\.com/openapi/"),
    (
        "google_api_client",
        r"//apis\.google\.com/js/(?:platform|api|client)",
    ),
    ("hcaptcha", r"//(?:js\.)?hcaptcha\.com/1/api\.js"),
    (
        "cloudflare_turnstile",
        r"//challenges\.cloudflare\.com/turnstile/",
    ),
    ("stripe_js", r"//js\.stripe\.com/v[0-9]"),
    ("paypal_sdk", r"//www\.paypal\.com/sdk/js"),
    // Korean payment gateways' checkout scripts.
    ("portone", r"//cdn\.iamport\.kr/|//cdn\.portone\.io/"),
    ("toss_payments", r"//js\.tosspayments\.com/"),
    ("kg_inicis", r"//stdpay\.inicis\.com/stdjs/"),
    ("nicepay", r"\.nicepay\.co\.kr/"),
    ("channel_talk", r"//cdn\.channel\.io/"),
    ("intercom", r"//widget\.intercom\.io/"),
    ("zendesk_widget", r"//static\.zdassets\.com/ekr/snippet\.js"),
    ("cookiebot", r"//consent\.cookiebot\.com/"),
    ("didomi", r"//sdk\.privacy-center\.org/"),
    ("trustarc", r"//consent\.trustarc\.com/"),
    ("usercentrics", r"//(?:app|web\.cmp)\.usercentrics\.eu/"),
    ("sourcepoint", r"//cdn\.privacy-mgmt\.com/|//sourcepoint\."),
    ("quantcast_choice", r"//cmp\.quantcast\.com/"),
    (
        "tealium",
        r"//tags\.tiqcdn\.com/utag/|/utag(?:\.sync)?\.js(?:$|[?#])",
    ),
    ("adobe_launch", r"//assets\.adobedtm\.com/"),
    ("amplitude", r"//cdn\.amplitude\.com/"),
    ("mixpanel", r"//cdn[0-9]*\.mxpnl\.com/"),
    ("segment", r"//cdn\.segment\.com/analytics\.js/"),
    ("hotjar", r"//static\.hotjar\.com/c/hotjar-"),
    (
        "microsoft_clarity",
        r"//www\.clarity\.ms/tag/|//scripts\.clarity\.ms/",
    ),
    // Its 2025 script is `pa-` and the site's own ID, on plausible.io or a
    // proxy the site runs.
    (
        "plausible",
        r"//plausible\.io/js/|/js/pa-[A-Za-z0-9_-]{20,24}\.js(?:$|[?#])",
    ),
    ("matomo", r"(?i)/(?:matomo|piwik)\.js(?:$|[?#])"),
    ("chartbeat", r"//static\.chartbeat\.com/js/"),
    ("akamai_mpulse", r"//s\.go-mpulse\.net/boomerang/"),
    ("new_relic", r"//js-agent\.newrelic\.com/"),
    ("datadog_rum", r"//www\.datadoghq-browser-agent\.com/"),
    (
        "hubspot",
        r"//js\.(?:hs-scripts\.com|hs-analytics\.net|hsforms\.net)/",
    ),
    (
        "meta_pixel",
        r"//connect\.facebook\.net/(?:[a-z]{2}_[A-Z]{2}/fbevents\.js|signals/)",
    ),
    ("tiktok_pixel", r"//analytics\.tiktok\.com/i18n/pixel/"),
    ("linkedin_insight", r"//snap\.licdn\.com/li\.lms-analytics/"),
    ("x_pixel", r"//static\.ads-twitter\.com/uwt\.js"),
    ("microsoft_uet", r"//bat\.bing\.com/bat\.js"),
    ("criteo", r"//static\.criteo\.net/js/ld/"),
    ("taboola", r"//cdn\.taboola\.com/libtrc/"),
    ("outbrain", r"//widgets\.outbrain\.com/outbrain\.js"),
    ("yandex_metrica", r"//mc\.yandex\.ru/metrika/"),
    ("baidu_tongji", r"//hm\.baidu\.com/hm\.js"),
    ("monetate", r"//[a-z]+\.monetate\.net/"),
    ("optimizely", r"//cdn\.optimizely\.com/js/"),
    ("vwo", r"//dev\.visualwebsiteoptimizer\.com/"),
    // Korean web analytics and content recommendation.
    ("acecounter", r"\.acecounter\.com[:/]"),
    ("beusable", r"\.beusable\.net/"),
    ("dable", r"\.dable\.io/"),
    // Each service's documented tag.
    ("the_trade_desk", r"//js\.adsrvr\.org/"),
    ("pubmatic", r"//ads\.pubmatic\.com/AdServer/js/"),
    ("sixsense", r"//j\.6sc\.co/"),
    ("snap_pixel", r"//sc-static\.net/scevent\.min\.js"),
    ("pinterest_tag", r"//s\.pinimg\.com/ct/core\.js"),
    (
        "klaviyo",
        r"//static(?:-tracking)?\.klaviyo\.com/onsite/js/",
    ),
    ("clearbit", r"//tag\.clearbitscripts\.com/"),
    (
        "yahoo_japan_ads",
        r"//s\.yimg\.jp/images/listing/tool/cv/ytag\.js",
    ),
    (
        "ethicalads",
        r"//media\.ethicalads\.io/media/client/(?:v[0-9.]+/)?ethicalads(?:\.min)?\.js",
    ),
    // APM agents, served by the monitored site itself or the vendor's CDN.
    ("dynatrace_rum", r"/ruxitagent(?:js)?_"),
    (
        "appdynamics_browser",
        r"/adrum(?:-ext|-latest|-[0-9][0-9.]*)?(?:\.[0-9a-f]{8,})?\.js(?:$|[?#])",
    ),
];

const VERSION: &str = r"([0-9][0-9A-Za-z.+-]{0,39})";

struct Signatures {
    set: RegexSet,
    /// The rules that name a version, compiled again to capture it.
    each: Vec<Option<Regex>>,
    ids: Vec<&'static str>,
}

fn compile(rules: &'static [(&'static str, &'static str)]) -> Signatures {
    let patterns: Vec<String> = rules
        .iter()
        .map(|(_, pattern)| pattern.replace('§', VERSION))
        .collect();
    Signatures {
        set: RegexSet::new(&patterns).expect("valid front-end signatures"),
        each: rules
            .iter()
            .zip(&patterns)
            .map(|((_, rule), pattern)| {
                rule.contains('§')
                    .then(|| Regex::new(pattern).expect("valid front-end signature"))
            })
            .collect(),
        ids: rules.iter().map(|(id, _)| *id).collect(),
    }
}

static SCRIPTS: LazyLock<Signatures> = LazyLock::new(|| compile(SCRIPT_SIGNATURES));
static PAGES: LazyLock<Signatures> = LazyLock::new(|| compile(PAGE_SIGNATURES));
// A combined Unicode word-boundary search can lose the regex engine's fast
// literal search across an entire multilingual page. Individual rules retain
// their own prefilters; keep the same patterns and separate version eligibility.
static PAGE_EACH: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    PAGE_SIGNATURES
        .iter()
        .map(|(_, pattern)| {
            Regex::new(&pattern.replace('§', VERSION)).expect("valid front-end signature")
        })
        .collect()
});
static MARKERS: LazyLock<Signatures> = LazyLock::new(|| compile(URL_MARKERS));
static GENERATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<meta\b[^>]*\bname\s*=\s*["']generator["'][^>]*>"#)
        .expect("valid generator pattern")
});
static CONTENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bcontent\s*=\s*["']([^"']{1,120})["']"#).expect("valid content pattern")
});
static ASSET_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)<(?:script|link)\b[^>]*?\s(?:src|href)\s*=\s*["']([^"'\s<>]{1,512})["']"#)
        .expect("valid asset URL pattern")
});
// A package and its version as CDNs path them, a version in a file name, and
// WordPress's own version on the core assets it serves. The paths, not the
// hosts, are matched, so a company's mirror of a public CDN counts too:
// `/npm/vue@3.4.21/` and unpkg's `/vue@3.4.21/`, cdnjs's and Google's
// `/ajax/libs/jquery/3.7.1/`, jQuery's `/ui/1.13.2/jquery-ui.js`.
// Under `/npm/` a dist tag (`@latest`) names the package too; elsewhere only
// a version does, so `/users/jquery@example.com/` is no package.
static CDN_PACKAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)/(?:npm/((?:@[a-z0-9._-]+/)?[a-z0-9._-]+)@(?:([0-9][0-9a-z.+-]{0,39})|[a-z0-9._-]*)|((?:@[a-z0-9._-]+/)?[a-z0-9._-]+)@([0-9][0-9a-z.+-]{0,39}))(?:[/?#]|$)")
        .expect("valid CDN package pattern")
});
static CDN_LIBRARY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)/ajax/libs/([a-z0-9._-]+)/([0-9][0-9a-z.+-]{0,39})/")
        .expect("valid CDN library pattern")
});
static JQUERY_UI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)/ui/([0-9][0-9.]*[0-9])/jquery-ui(?:\.min)?\.(?:js|css)")
        .expect("valid jQuery UI pattern")
});
static FILE_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)/(jquery-ui|jquery-migrate|jquery|bootstrap|vue|react-dom|react|angular|lodash|moment|knockout|backbone|underscore|handlebars|modernizr|select2|swiper|d3|leaflet)[.-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:[.-](?:slim|min|bundle|umd|prod|production))*\.(?:js|css)(?:$|[?#])")
        .expect("valid versioned file pattern")
});
static WORDPRESS_ASSET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)/wp-includes/(?:(js/jquery/jquery)(?:\.min)?\.js|js/wp-emoji-release\.min\.js|css/dist/block-library/style(?:\.min)?\.css)\?ver=([0-9][0-9.]*[0-9])")
        .expect("valid WordPress asset pattern")
});

/// The product a CDN package or a versioned file is.
fn package_product(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "react" | "react-dom" => "react",
        "vue" | "@vue/runtime-dom" | "@vue/runtime-core" => "vue",
        "nuxt" => "nuxt",
        "@angular/core" => "angular",
        "angular" | "angular.js" | "angularjs" => "angularjs",
        "svelte" => "svelte",
        "ember-source" | "ember.js" => "ember",
        "preact" => "preact",
        "lit" | "lit-html" | "lit-element" => "lit",
        "alpinejs" => "alpine_js",
        "htmx.org" | "htmx" => "htmx",
        "@hotwired/turbo" => "hotwire_turbo",
        "backbone" | "backbone.js" => "backbone",
        "knockout" => "knockout",
        "bootstrap" | "twitter-bootstrap" => "bootstrap",
        "vuetify" => "vuetify",
        "element-plus" => "element_plus",
        "element-ui" => "element_ui",
        "quasar" => "quasar",
        "font-awesome" | "@fortawesome/fontawesome-free" => "font_awesome",
        "jquery" => "jquery",
        "jqueryui" | "jquery-ui" | "jquery-ui-dist" => "jquery_ui",
        "jquery-migrate" => "jquery_migrate",
        "lodash" | "lodash.js" => "lodash",
        "underscore" | "underscore.js" => "underscore",
        "moment" | "moment.js" => "moment",
        "dayjs" => "dayjs",
        "core-js" | "core-js-bundle" => "core_js",
        "axios" => "axios",
        "socket.io" | "socket.io-client" => "socket_io",
        "dompurify" => "dompurify",
        "chart.js" => "chart_js",
        "d3" | "d3js" => "d3",
        "three" | "three.js" | "threejs" => "three_js",
        "leaflet" => "leaflet",
        "highcharts" => "highcharts",
        "echarts" => "echarts",
        "gsap" => "gsap",
        "swiper" => "swiper",
        "video.js" => "video_js",
        "hls.js" => "hls_js",
        "select2" => "select2",
        "@popperjs/core" | "popper.js" => "popper",
        "handlebars" | "handlebars.js" => "handlebars",
        "modernizr" => "modernizr",
        "zepto" | "zepto.js" => "zepto",
        "prototype" => "prototype",
        "mootools" => "mootools",
        "pdfjs-dist" | "pdf.js" => "pdf_js",
        "tinymce" => "tinymce",
        "ckeditor" | "ckeditor5" => "ckeditor",
        "quill" => "quill",
        "sweetalert2" => "sweetalert2",
        "hammer.js" | "hammerjs" => "hammer_js",
        "@sentry/browser" => "sentry",
        "slick-carousel" => "slick",
        "aos" => "aos",
        "html5shiv" => "html5shiv",
        "respond.js" => "respond_js",
        "fullpage.js" => "fullpage_js",
        "scrollmagic" => "scrollmagic",
        "malihu-custom-scrollbar-plugin" => "mcustomscrollbar",
        "owl.carousel" => "owl_carousel",
        "bxslider" => "bxslider",
        "jquery.easing" => "jquery_easing",
        "jquery-form" => "jquery_form",
        "jquery-cookie" | "jquery.cookie" => "jquery_cookie",
        "highlight.js" | "@highlightjs/cdn-assets" => "highlight_js",
        "requirejs" | "require.js" => "requirejs",
        "fontfaceobserver" => "fontfaceobserver",
        "@webcomponents/webcomponentsjs" => "webcomponentsjs",
        "web-animations-js" => "web_animations_js",
        "firebase" => "firebase",
        "@amplitude/analytics-browser" | "amplitude-js" => "amplitude",
        "mixpanel-browser" => "mixpanel",
        _ => return None,
    })
}

/// A product in the table, with the version found for it.
pub(crate) fn known(id: &str, version: Option<&str>) -> Option<Detection> {
    let (id, name, category) = PRODUCTS.iter().find(|(known, _, _)| *known == id)?;
    Some(Detection {
        product_id: (*id).into(),
        name: (*name).into(),
        category,
        version: version.filter(|v| valid_version(v)).map(str::to_string),
        signal: "",
    })
}

/// Keeps one entry per product: the first version found, or none until one is.
pub(crate) fn merge(found: &mut Vec<Detection>, detection: Detection) {
    match found
        .iter_mut()
        .find(|item| item.product_id == detection.product_id)
    {
        Some(item) if item.version.is_none() => item.version = detection.version,
        Some(_) => {}
        None => found.push(detection),
    }
}

fn scan_matches(
    signatures: &Signatures,
    text: &str,
    found: &mut Vec<Detection>,
    indexes: impl IntoIterator<Item = usize>,
) {
    for index in indexes {
        let version = signatures.each[index]
            .as_ref()
            .and_then(|rule| rule.captures(text))
            .and_then(|captures| captures.get(1))
            .map(|version| version.as_str());
        if let Some(detection) = known(signatures.ids[index], version) {
            merge(found, detection);
        }
    }
}

fn scan(signatures: &Signatures, text: &str, found: &mut Vec<Detection>) {
    scan_matches(signatures, text, found, signatures.set.matches(text));
}

fn scan_page(text: &str, found: &mut Vec<Detection>) {
    if text.is_ascii() {
        scan(&PAGES, text, found);
    } else {
        scan_matches(
            &PAGES,
            text,
            found,
            PAGE_EACH
                .iter()
                .enumerate()
                .filter_map(|(index, rule)| rule.is_match(text).then_some(index)),
        );
    }
}

/// Every technology this body declares, one entry per product.
pub(crate) fn detect(body: &str, kind: Kind) -> Vec<Detection> {
    use crate::service_map_servers::{detect_exposures, Exposed};
    let mut found = Vec::new();
    let exposed = match kind {
        Kind::Script => Exposed::Script,
        Kind::Page => Exposed::Page,
        Kind::Data => Exposed::Error,
    };
    for detection in detect_exposures(body, exposed) {
        merge(&mut found, detection);
    }
    match kind {
        Kind::Script => {
            if let Some(detection) = next_version(body).and_then(|v| known("next_js", Some(&v))) {
                merge(&mut found, detection);
            }
            scan(&SCRIPTS, body, &mut found);
        }
        Kind::Page => {
            scan_page(body, &mut found);
            for tag in GENERATOR.find_iter(body).take(4) {
                if let Some(detection) = CONTENT
                    .captures(tag.as_str())
                    .and_then(|captures| generator(&captures[1]))
                {
                    merge(&mut found, detection);
                }
            }
            for url in ASSET_URL.captures_iter(body).take(MAX_PAGE_URLS) {
                for detection in detect_url(&url[1]) {
                    merge(&mut found, detection);
                }
            }
            for detection in crate::service_map_servers::detect_body(body) {
                merge(&mut found, detection);
            }
        }
        Kind::Data => {
            for detection in crate::service_map_servers::detect_body(body) {
                merge(&mut found, detection);
            }
        }
    }
    found
}

/// Leaves out the source map of a library's own file: `jquery.min.js`, whose
/// banner or URL names jQuery, maps jQuery's public source. A bundle's name
/// (`main.3f2a.js`) names none of what it carries, so its map stays a finding.
/// In a crawl of 613 sites this took the finding from 156 sites to 76; most
/// were Swiper, jQuery, Moment.js and Bootstrap served by the site itself.
pub(crate) fn drop_library_source_map(found: &mut Vec<Detection>, url: &str) {
    if !found.iter().any(|item| item.product_id == "source_map") {
        return;
    }
    let file = url
        .split(['?', '#'])
        .next()
        .and_then(|path| path.rsplit('/').next())
        .unwrap_or_default();
    let tokens: Vec<String> = file
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    // Run together, as `owl.carousel.min.js` spells Owl Carousel; Chart.js's
    // file is `chart.min.js`.
    let names = |name: &str| {
        let name: String = name
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        let name = match name.strip_suffix("js") {
            Some(stem) if stem.len() >= 3 => stem.to_string(),
            _ => name,
        };
        // Stop once the run is as long as the name: a run never shrinks, and
        // a file name of thousands of tokens (the path is not bounded) made
        // every start join all the rest.
        (0..tokens.len()).any(|start| {
            let mut joined = String::new();
            for token in &tokens[start..] {
                joined.push_str(token);
                if joined.len() >= name.len() {
                    return joined == name;
                }
            }
            false
        })
    };
    let library = found
        .iter()
        .chain(&detect_url(url))
        .filter(|item| matches!(item.category, FRAMEWORK | UI | LIBRARY | ANALYTICS))
        .any(|item| names(&item.product_id) || names(&item.name));
    if library {
        found.retain(|item| item.product_id != "source_map");
    }
}

/// What an asset URL names: a CDN package and version, a versioned file, or a
/// product's build directory or host. A row's own URL is read this way without
/// its body, as are the scripts and stylesheets a page links.
pub(crate) fn detect_url(url: &str) -> Vec<Detection> {
    let mut found = Vec::new();
    let mut add = |id: Option<&str>, version: Option<&str>| {
        if let Some(detection) = id.and_then(|id| known(id, version)) {
            merge(&mut found, detection);
        }
    };
    if let Some(captures) = CDN_PACKAGE.captures(url) {
        add(
            captures
                .get(1)
                .or_else(|| captures.get(3))
                .and_then(|package| package_product(package.as_str())),
            captures
                .get(2)
                .or_else(|| captures.get(4))
                .map(|v| v.as_str()),
        );
    }
    for captures in [&CDN_LIBRARY, &FILE_VERSION]
        .into_iter()
        .filter_map(|rule| rule.captures(url))
    {
        add(
            package_product(&captures[1]),
            captures.get(2).map(|v| v.as_str()),
        );
    }
    if let Some(captures) = JQUERY_UI.captures(url) {
        add(Some("jquery_ui"), Some(&captures[1]));
    }
    if let Some(captures) = WORDPRESS_ASSET.captures(url) {
        // WordPress versions its core assets with its own release, and the
        // jQuery it bundles with jQuery's.
        let product = if captures.get(1).is_some() {
            "jquery"
        } else {
            "wordpress"
        };
        add(Some(product), captures.get(2).map(|v| v.as_str()));
    }
    for index in MARKERS.set.matches(url).iter() {
        let version = MARKERS.each[index]
            .as_ref()
            .and_then(|rule| rule.captures(url))
            .and_then(|captures| captures.get(1));
        add(Some(MARKERS.ids[index]), version.map(|v| v.as_str()));
    }
    found
}

/// A generator's name and version: "WordPress 6.5.2", "Astro v4.0.3",
/// "Drupal 10 (https://www.drupal.org)", or a name alone. A product in the
/// table keeps its own name.
fn generator(content: &str) -> Option<Detection> {
    let mut words = Vec::new();
    let mut version = None;
    for word in content.split_whitespace().take(6) {
        if words.is_empty() {
            let word = word.trim_end_matches([',', ';']);
            if let Some((name, number)) = word.rsplit_once('-').filter(|(name, number)| {
                name.starts_with(|c: char| c.is_ascii_alphabetic())
                    && number
                        .trim_start_matches(['v', 'V'])
                        .starts_with(|c: char| c.is_ascii_digit())
            }) {
                words.push(name);
                version = Some(number.trim_start_matches(['v', 'V']).to_string());
                break;
            }
        }
        let candidate = word
            .strip_prefix(['v', 'V'])
            .filter(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
            .unwrap_or(word);
        if candidate.starts_with(|c: char| c.is_ascii_digit()) {
            version = Some(
                candidate
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
                    .collect::<String>(),
            );
            break;
        }
        words.push(word);
    }
    let name = words.join(" ");
    let lower = name.to_ascii_lowercase();
    if let Some((id, _, _)) = PRODUCTS.iter().find(|(_, product, _)| {
        let product = product.to_ascii_lowercase();
        lower.starts_with(&product)
            && !lower[product.len()..].starts_with(|c: char| c.is_ascii_alphanumeric())
    }) {
        return known(id, version.as_deref());
    }
    let product_id: String = lower
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    let name_ok = name.len() <= 40
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '!' | '+' | '_' | '-'));
    (name_ok && !product_id.is_empty() && product_id.len() <= 40).then(|| Detection {
        product_id,
        name,
        category: CMS,
        version: version.filter(|v| valid_version(v)),
        signal: "",
    })
}

pub(crate) fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 40
        && version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// The version Next.js's client runtime names in this script, if it does.
fn next_version(script: &str) -> Option<String> {
    const ANCHOR: &str = "window.next={version:";
    for (at, _) in script.match_indices(ANCHOR) {
        let rest = &script[at + ANCHOR.len()..];
        // The App Router writes the literal. The Pages Router names a variable
        // assigned earlier in the bundle. ponytail: the nearest `name="…"`
        // before the anchor is taken as its value; a parser would be exact.
        if let Some(literal) = rest.strip_prefix('"') {
            if let Some(version) = literal.split('"').next().filter(|v| valid_version(v)) {
                return Some(version.to_string());
            }
            continue;
        }
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$'))
            .collect();
        if name.is_empty() {
            continue;
        }
        let mut start = at.saturating_sub(4096);
        while !script.is_char_boundary(start) {
            start += 1;
        }
        let before = &script[start..at];
        if let Some(found) = before.rfind(&format!("{name}=\"")) {
            let literal = &before[found + name.len() + 2..];
            if let Some(version) = literal.split('"').next().filter(|v| valid_version(v)) {
                return Some(version.to_string());
            }
        }
    }
    None
}

// Only the response body is kept; serde skips every other field of the row.
#[derive(Deserialize)]
struct DiskRow {
    id: Uuid,
    response: Option<DiskResponse>,
}

#[derive(Deserialize)]
struct DiskResponse {
    #[serde(default)]
    body_preview: String,
    #[serde(default)]
    body_encoding: BodyEncoding,
}

/// A body as text to scan: as stored when UTF-8, or, when it was stored as
/// base64 because it is not (an EUC-KR page), its bytes read lossily. Every
/// signature is ASCII, which any of those encodings keeps.
pub(crate) fn scan_text(body: String, encoding: BodyEncoding) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    match encoding {
        BodyEncoding::Utf8 => Some(body),
        BodyEncoding::Base64 => STANDARD
            .decode(body.as_bytes())
            .ok()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
    }
}

/// One retained row's response body as text to scan, or None when it cannot
/// be shown to be this record's body.
pub(crate) fn read_body(file: &mut File, locator: BodyLocator, record_id: Uuid) -> Option<String> {
    let len = locator.len as usize;
    if len == 0 || len > MAX_ROW_BYTES {
        return None;
    }
    file.seek(SeekFrom::Start(locator.offset)).ok()?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes).ok()?;
    let row: DiskRow = serde_json::from_slice(&bytes).ok()?;
    let response = row.response?;
    (row.id == record_id).then_some(())?;
    scan_text(response.body_preview, response.body_encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_page_scan_equivalent(body: &str) {
        let mut original = Vec::new();
        scan(&PAGES, body, &mut original);
        let mut optimized = Vec::new();
        scan_page(body, &mut optimized);
        assert_eq!(optimized, original, "page signature differential: {body:?}");
        let combined: Vec<_> = PAGES.set.matches(body).into_iter().collect();
        let separate: Vec<_> = PAGE_EACH
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| rule.is_match(body).then_some(index))
            .collect();
        assert_eq!(separate, combined, "page rule-index differential: {body:?}");
    }

    #[test]
    fn unicode_page_matching_preserves_boundaries_malformed_tags_and_precedence() {
        let surroundings = [
            "", "ascii", "é", "한글", "中", "\u{0301}", "\u{2003}", "\u{00a0}", "😀", "\0", "\r\n",
        ];
        let signals = [
            r#"<app ng-version="17.2.1">"#,
            r#"<app ng-version="18.0.0">"#,
            r#"<div data-v-ab12cd34>"#,
            r#"<div data-v-ab12cd34x>"#,
            r#"<div class="svelte-abc123">"#,
            r#"<div class="xsvelte-abc123">"#,
            r#"<div class="ember-view">"#,
            r#"<div class="ember-view字">"#,
            r#"<div q:version="1.2.3" q:container="">"#,
            r#"<div data-bind="text: name">"#,
            r#"<div hx-get="/">"#,
            "<div\u{2003}ng-controller=",
            "é_nghost-a",
            " _nghost-a",
            "<div class='unterminated",
            "<script id='__NEXT_DATA__'",
            "<meta name=",
        ];
        for prefix in surroundings {
            for suffix in surroundings {
                for signal in signals {
                    assert_page_scan_equivalent(&format!("{prefix}{signal}{suffix}"));
                }
            }
        }
        assert_page_scan_equivalent(
            r#"한글 <app ng-version="17.2.1"><app ng-version="18.0.0"><div q:version="1.2.3">"#,
        );
        assert_page_scan_equivalent(&format!(
            "{}<div data-v-ab12cd34>",
            "<p>한글 中 😀</p>".repeat(4096)
        ));
        assert_page_scan_equivalent(&format!("{}é", "<p>ordinary ASCII text</p>".repeat(4096)));
        let mut first = Vec::new();
        scan_page(
            r#"한글 <app ng-version="17.2.1"><app ng-version="18.0.0"><div q:version="1.2.3"><div q:version="2.0.0">"#,
            &mut first,
        );
        let versions = found(first);
        assert!(versions.contains(&one("angular", Some("17.2.1"))));
        assert!(versions.contains(&one("qwik", Some("1.2.3"))));
        assert_page_scan_equivalent(&format!(
            "{}' data-bind='text: name'>",
            "<div class='".repeat(256)
        ));
    }

    #[test]
    #[ignore = "requires a reserved, uncontended native timing run"]
    fn measure_unicode_page_match_paths() {
        let sized = |unit: &str, bytes: usize| unit.repeat(bytes / unit.len());
        let ascii = sized("<p>ordinary page text</p>", 1_048_576);
        let unicode = sized("<p>한글 中文 é page text</p>", 1_048_576);
        let positive = r#"<app ng-version="17.2.1"><div data-v-ab12cd34 class="svelte-abc123"><div q:version="1.2.3"><div hx-get="/">"#;
        let mut cases = vec![
            (
                "ascii-small-negative",
                sized("<p>ordinary page text</p>", 4096),
            ),
            (
                "unicode-small-negative",
                sized("<p>한글 中文 é page text</p>", 4096),
            ),
            ("ascii-large-negative", ascii.clone()),
            ("unicode-large-negative", unicode.clone()),
            ("ascii-late-positive", format!("{ascii}{positive}")),
            ("unicode-late-positive", format!("{unicode}{positive}")),
            ("ascii-dense-positive", sized(positive, 1_048_576)),
            (
                "unicode-dense-positive",
                sized(&format!("한글 中文 é{positive}"), 1_048_576),
            ),
        ];
        for (label, at) in [
            ("sparse-unicode-start", 0),
            ("sparse-unicode-middle", ascii.len() / 2),
            ("sparse-unicode-end", ascii.len()),
        ] {
            let mut body = ascii.clone();
            body.insert(at, 'é');
            cases.push((label, body));
        }
        for (label, body) in cases {
            assert_page_scan_equivalent(&body);
            let mut detections = Vec::new();
            scan_page(&body, &mut detections);
            assert_eq!(
                !detections.is_empty(),
                label.contains("positive"),
                "{label}"
            );
            let measure = |selected: bool| {
                let started = std::time::Instant::now();
                let mut found = Vec::new();
                if selected {
                    scan_page(std::hint::black_box(&body), &mut found);
                } else {
                    scan(&PAGES, std::hint::black_box(&body), &mut found);
                }
                std::hint::black_box(found);
                started.elapsed()
            };
            // Alternate order so the selected path is not always measured last.
            for pair in 0..5 {
                let selected_first = pair % 2 != 0;
                let first = measure(selected_first);
                let second = measure(!selected_first);
                let (combined, selected) = if selected_first {
                    (second, first)
                } else {
                    (first, second)
                };
                eprintln!(
                    "page {label}: bytes={} pair={pair} selected_first={selected_first} combined={combined:?} selected={selected:?}",
                    body.len()
                );
            }
        }
    }

    fn found(items: Vec<Detection>) -> Vec<(String, Option<String>)> {
        items
            .into_iter()
            .map(|item| (item.product_id, item.version))
            .collect()
    }

    fn one(id: &str, version: Option<&str>) -> (String, Option<String>) {
        (id.into(), version.map(str::to_string))
    }

    #[test]
    fn every_rule_compiles_and_names_a_product() {
        for (id, _) in SCRIPT_SIGNATURES
            .iter()
            .chain(PAGE_SIGNATURES)
            .chain(URL_MARKERS)
        {
            assert!(known(id, None).is_some(), "{id} is not in PRODUCTS");
        }
        // Every name is one the UI and the CLI accept, or they drop it.
        let shape = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9 .!+_-]{0,39}$").unwrap();
        for (id, name, category) in PRODUCTS {
            assert!(CATEGORIES.contains(category));
            assert!(shape.is_match(name), "{id}: {name}");
        }
        assert_eq!(SCRIPTS.ids.len(), SCRIPT_SIGNATURES.len());
        assert_eq!(PAGES.ids.len(), PAGE_SIGNATURES.len());
        assert_eq!(MARKERS.ids.len(), URL_MARKERS.len());
    }

    #[test]
    fn next_version_reads_the_runtime_literal_or_its_variable() {
        // The App Router form, as nextjs.org ships it.
        assert_eq!(
            next_version(r#"n()}window.next={version:"16.5.0-canary.9",appDir:!0},("function""#),
            Some("16.5.0-canary.9".into())
        );
        // The Pages Router form: a variable assigned earlier in the bundle.
        assert_eq!(
            next_version(r#"let s="13.4.7",o=null;function f(){}window.next={version:s,router:r}"#),
            Some("13.4.7".into())
        );
        assert_eq!(
            next_version(r#"window.next={version:"<script>",appDir:!0}"#),
            None
        );
        assert_eq!(next_version(r#"window.next={version:x,router:r}"#), None);
    }

    // One sample per script rule, as each library writes it.
    #[test]
    fn scripts_name_their_technologies_by_banner_or_runtime_value() {
        let samples: &[(&str, &str, Option<&str>)] = &[
            (r#"{bundleType:0,version:"18.2.0",rendererPackageName:"react-dom"}"#, "react", Some("18.2.0")),
            ("/** @license React v17.0.2\n * react-dom.production.min.js", "react", Some("17.0.2")),
            (r#""undefined"!=typeof __REACT_DEVTOOLS_GLOBAL_HOOK__"#, "react", None),
            ("/**\n* @vue/shared v3.4.21\n* (c) 2018-present Yuxi (Evan) You\n**/", "vue", Some("3.4.21")),
            ("/*!\n * Vue.js v2.7.16\n * (c) 2014-2023 Evan You", "vue", Some("2.7.16")),
            ("/**\n * vue v3.4.21\n * (c) 2018-present Yuxi (Evan) You", "vue", Some("3.4.21")),
            (r#"function Ze(e){return!!(e&&!0===e.__v_isRef)}"#, "vue", None),
            (r#"versions:{get nuxt(){return"3.8.2"},get vue(){return e.vueApp.version}}"#, "nuxt", Some("3.8.2")),
            ("window.__NUXT__", "nuxt", None),
            ("/**\n * @license Angular v17.1.0\n * (c) 2010-2022 Google LLC.", "angular", Some("17.1.0")),
            ("static{this.ɵcmp=ve({type:t,selectors:[[\"app-root\"]]})}", "angular", None),
            ("/*\n AngularJS v1.8.2\n @license AngularJS v1.8.2\n (c) 2010-2020 Google LLC.", "angularjs", Some("1.8.2")),
            (r#"{full:"1.8.3",major:1,minor:8,dot:3,codeName:"ultimate-farewell"}"#, "angularjs", Some("1.8.3")),
            (r#"typeof window<"u"&&(window.__svelte||(window.__svelte={v:new Set})).v.add("4")"#, "svelte", Some("4")),
            ("/*!\n * @overview  Ember - JavaScript Application Framework\n * @license   Licensed under MIT license\n * @version   4.12.0\n */", "ember", Some("4.12.0")),
            (r#"(globalThis.litHtmlVersions??=[]).push("3.1.0")"#, "lit", Some("3.1.0")),
            (r#"version:"3.13.3",flushAndStopDeferringMutations:Ft"#, "alpine_js", Some("3.13.3")),
            (r#"config:{historyEnabled:!0,indicatorClass:"htmx-indicator",requestClass:"htmx-request"}"#, "htmx", None),
            ("//     Backbone.js 1.4.1\n", "backbone", Some("1.4.1")),
            ("/*!\n * Knockout JavaScript library v3.5.1\n", "knockout", Some("3.5.1")),
            ("/*!\n  * Bootstrap v5.3.2 (https://getbootstrap.com/)", "bootstrap", Some("5.3.2")),
            ("/*!\n* Vuetify v3.4.0\n* Forged by John Leider", "vuetify", Some("3.4.0")),
            ("/*! Element Plus v2.4.3 */", "element_plus", Some("2.4.3")),
            ("/*!\n * Quasar Framework v2.14.2\n * (c) 2015-present Razvan Stoenescu", "quasar", Some("2.14.2")),
            ("/*!\n * Font Awesome Free 6.5.1 by @fontawesome", "font_awesome", Some("6.5.1")),
            ("/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors */", "jquery", Some("3.7.1")),
            ("/*! jQuery v3.7.1 -ajax,-ajax/jsonp | (c) OpenJS Foundation */", "jquery", Some("3.7.1")),
            ("/*!\n * jQuery JavaScript Library v3.6.0\n", "jquery", Some("3.6.0")),
            ("/*! jQuery UI - v1.13.2 - 2022-07-14", "jquery_ui", Some("1.13.2")),
            ("/*! jQuery Migrate v3.4.1 | (c) OpenJS Foundation */", "jquery_migrate", Some("3.4.1")),
            ("/**\n * @license\n * Lodash <https://lodash.com/>\n", "lodash", None),
            ("//     Underscore.js 1.13.6\n//     https://underscorejs.org", "underscore", Some("1.13.6")),
            ("//! moment.js\n//! version : 2.29.4", "moment", Some("2.29.4")),
            (r#"push({version:"3.38.1",mode:"global",copyright:"© 2014-2024"})"#, "core_js", Some("3.38.1")),
            ("/*! Axios v1.6.7 Copyright (c) 2024 Matt Zabriskie and contributors */", "axios", Some("1.6.7")),
            ("/*!\n * Socket.IO v4.7.2\n * (c) 2014-2023 Guillermo Rauch", "socket_io", Some("4.7.2")),
            ("/*! @license DOMPurify 3.0.6 | (c) Cure53 and other contributors */", "dompurify", Some("3.0.6")),
            ("/*!\n * Chart.js v4.4.0\n * https://www.chartjs.org", "chart_js", Some("4.4.0")),
            ("// https://d3js.org v7.8.5 Copyright 2010-2023 Mike Bostock", "d3", Some("7.8.5")),
            (r#"window.__THREE__="160""#, "three_js", Some("160")),
            ("console.warn(\"WARNING: Multiple instances of Three.js being imported.\")", "three_js", None),
            ("/* @preserve\n * Leaflet 1.9.4, a JS library for interactive maps. https://leafletjs.com", "leaflet", Some("1.9.4")),
            ("/*\n Highcharts JS v11.2.0 (2023-10-30)\n", "highcharts", Some("11.2.0")),
            ("/*!\n * GSAP 3.12.2\n * https://greensock.com", "gsap", Some("3.12.2")),
            ("/**\n * Swiper 11.0.5\n * Most modern mobile touch slider", "swiper", Some("11.0.5")),
            ("/**\n * @license\n * Video.js 8.6.1 <http://videojs.com/>", "video_js", Some("8.6.1")),
            ("/*! Select2 4.0.13 | https://github.com/select2/select2/blob/master/LICENSE.md */", "select2", Some("4.0.13")),
            ("/**\n * @popperjs/core v2.11.8 - MIT License\n */", "popper", Some("2.11.8")),
            ("/**!\n\n @license\n handlebars v4.7.8\n", "handlebars", Some("4.7.8")),
            ("/*! modernizr 3.6.0 (Custom Build) | MIT *", "modernizr", Some("3.6.0")),
            ("/* Zepto v1.2.0 - zepto event ajax form ie - zeptojs.com/license */", "zepto", Some("1.2.0")),
            ("/*  Prototype JavaScript framework, version 1.7.3\n", "prototype", Some("1.7.3")),
            (r#"this.MooTools={version:"1.6.0",build:"529422872adfff401b901b8b6c7ca5114ee95e2b"}"#, "mootools", Some("1.6.0")),
            (r#"const pdfjsVersion="3.11.174""#, "pdf_js", Some("3.11.174")),
            ("/**\n * TinyMCE version 6.7.0 (2023-08-30)\n */", "tinymce", Some("6.7.0")),
            (r#"d={timestamp:"N3OC",version:"4.22.1 (Standard)",revision:"7a9e5f8"}"#, "ckeditor", Some("4.22.1")),
            ("window.CKEDITOR_VERSION=e", "ckeditor", None),
            ("/*!\n * Quill Editor v1.3.7\n * https://quilljs.com/", "quill", Some("1.3.7")),
            ("/*!\n* sweetalert2 v11.10.1\n* Released under the MIT License.\n*/", "sweetalert2", Some("11.10.1")),
            ("/*! Hammer.JS - v2.0.7 - 2016-04-22", "hammer_js", Some("2.0.7")),
            ("/*! @sentry/browser 7.81.1 (6f1c1f0) | https://github.com/getsentry/sentry-javascript */", "sentry", Some("7.81.1")),
            ("/*! highlight.js v9.18.1 | BSD3 License | git.io/hljslicense */", "highlight_js", Some("9.18.1")),
            ("/*!\n  Highlight.js v11.9.0 (git: f47103d4f1)\n", "highlight_js", Some("11.9.0")),
            ("/** vim: et:ts=4:sw=4:sts=4\n * @license RequireJS 2.3.6 Copyright jQuery Foundation", "requirejs", Some("2.3.6")),
            (r#"n()}window.next={version:"14.2.3",appDir:!0}"#, "next_js", Some("14.2.3")),
        ];
        for (sample, id, version) in samples {
            assert!(
                found(detect(sample, Kind::Script)).contains(&one(id, *version)),
                "{id} {version:?} in {sample}: {:?}",
                found(detect(sample, Kind::Script))
            );
        }
        // Neighbouring literals name nothing: another library's version field,
        // a plugin's requirement, Lodash's credit to Underscore.
        for sample in [
            r#"other.version:"9.9.9""#,
            "requires jQuery v1.7 or later",
            "/** @license Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE */",
            "console.log(1)",
        ] {
            let names: Vec<_> = found(detect(sample, Kind::Script))
                .into_iter()
                .filter(|(id, _)| id != "lodash")
                .collect();
            assert!(names.is_empty(), "{sample}: {names:?}");
        }
        // Page markup is not read from scripts.
        assert!(detect(r#"<app ng-version="17.1.0">"#, Kind::Script).is_empty());
    }

    // One sample per page rule, the generator meta and a linked asset.
    #[test]
    fn pages_name_their_technologies_by_markup_generator_and_assets() {
        let samples: &[(&str, &str, Option<&str>)] = &[
            (
                r#"<app-root ng-version="17.1.0"></app-root>"#,
                "angular",
                Some("17.1.0"),
            ),
            (r#"<div _ngcontent-ng-c2087410263="">"#, "angular", None),
            (r#"<html ng-app="shop">"#, "angularjs", None),
            (";window.NREUM||(NREUM={});NREUM.init={}", "new_relic", None),
            (
                "var _sf_async_config = _sf_async_config || {};",
                "chartbeat",
                None,
            ),
            (
                "window.plausible = window.plausible || function() {}",
                "plausible",
                None,
            ),
            (r#"<div data-ng-controller="Cart">"#, "angularjs", None),
            (
                r#"<script id="__NEXT_DATA__" type="application/json">"#,
                "next_js",
                None,
            ),
            (
                r#"<script>self.__next_f.push([1,""])</script>"#,
                "next_js",
                None,
            ),
            (r#"<div id="__nuxt"><div id="__layout">"#, "nuxt", None),
            (r#"<div id="root" data-reactroot="">"#, "react", None),
            (r#"<div data-v-1a2b3c4d class="card">"#, "vue", None),
            (r#"<div id="app" data-server-rendered="true">"#, "vue", None),
            (r#"<h1 class="title svelte-1x2y3z4">"#, "svelte", None),
            (
                r#"<body data-sveltekit-preload-data="hover">"#,
                "sveltekit",
                None,
            ),
            (
                r#"<div id="___gatsby"><div id="gatsby-focus-wrapper">"#,
                "gatsby",
                None,
            ),
            (
                r#"<astro-island uid="Z1" component-url="/_astro/Counter.js">"#,
                "astro",
                None,
            ),
            (
                r#"<script>window.__remixContext = {}</script>"#,
                "remix",
                None,
            ),
            (
                r#"<html q:container="paused" q:version="1.4.0">"#,
                "qwik",
                Some("1.4.0"),
            ),
            (r#"<div id="ember123" class="ember-view">"#, "ember", None),
            (r#"<div x-data="{ open: false }">"#, "alpine_js", None),
            (
                r#"<button hx-post="/clicked" hx-swap="outerHTML">"#,
                "htmx",
                None,
            ),
            (r#"<input wire:model="search">"#, "livewire", None),
            (r#"<turbo-frame id="messages">"#, "hotwire_turbo", None),
            (r#"<span data-bind="text: name"></span>"#, "knockout", None),
            (
                r#"<link rel="https://api.w.org/" href="https://example.com/wp-json/">"#,
                "wordpress",
                None,
            ),
            (
                r#"<script type="application/json" data-drupal-selector="drupal-settings-json">"#,
                "drupal",
                None,
            ),
            (
                r#"<link href="/media/system/js/core.js" rel="preload">"#,
                "joomla",
                None,
            ),
            (
                r#"<div data-mage-init='{"collapsible":{}}'>"#,
                "magento",
                None,
            ),
            (
                r#"<script>Shopify.theme = {"name":"Dawn"};</script>"#,
                "shopify",
                None,
            ),
            (
                r#"<img src="https://static.wixstatic.com/media/a.png">"#,
                "wix",
                None,
            ),
            (
                r#"<script>Static.SQUARESPACE_CONTEXT = {};</script>"#,
                "squarespace",
                None,
            ),
            (
                r#"j.src='https://www.googletagmanager.com/gtm.js?id='+i"#,
                "google_tag_manager",
                None,
            ),
            (
                r#"<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>"#,
                "google_analytics",
                None,
            ),
            (
                r#"<meta name="generator" content="WordPress 6.5.2">"#,
                "wordpress",
                Some("6.5.2"),
            ),
            (
                r#"<meta content="Astro v4.0.3" name="generator">"#,
                "astro",
                Some("4.0.3"),
            ),
            (
                r#"<meta name="generator" content="Joomla! - Open Source Content Management">"#,
                "joomla",
                None,
            ),
            (
                r#"<meta name="generator" content="Hugo 0.120.4">"#,
                "hugo",
                Some("0.120.4"),
            ),
            (
                r#"<script src="https://cdn.example.com/npm/vue@3.4.21/dist/vue.global.prod.js"></script>"#,
                "vue",
                Some("3.4.21"),
            ),
        ];
        let mut covered = std::collections::BTreeSet::new();
        for (sample, id, version) in samples {
            covered.extend(PAGES.set.matches(sample));
            for (prefix, suffix) in [
                ("", ""),
                ("한글 中文 é ", " 😀"),
                ("", "\n한글"),
                ("é", "字"),
                ("\u{2003}", "\u{0301}"),
            ] {
                assert_page_scan_equivalent(&format!("{prefix}{sample}{suffix}"));
            }
            assert!(
                found(detect(sample, Kind::Page)).contains(&one(id, *version)),
                "{id} {version:?} in {sample}: {:?}",
                found(detect(sample, Kind::Page))
            );
        }
        assert_eq!(
            covered.into_iter().collect::<Vec<_>>(),
            (0..PAGE_SIGNATURES.len()).collect::<Vec<_>>(),
            "Every page rule needs a positive differential fixture"
        );
        let drupal = generator("Drupal 10 (https://www.drupal.org)").unwrap();
        assert_eq!(
            (drupal.name, drupal.version),
            ("Drupal".into(), Some("10".into()))
        );
        assert_eq!(
            generator("Wix.com Website Builder").unwrap().product_id,
            "wix"
        );
        assert_eq!(generator("VuePress 2.0.0").unwrap().product_id, "vuepress");
        let mkdocs = generator("mkdocs-1.6.1, mkdocs-material-9.7.6").unwrap();
        assert_eq!(
            (mkdocs.product_id.as_str(), mkdocs.version.as_deref()),
            ("mkdocs", Some("1.6.1"))
        );
        let zensical = generator("zensical-0.0.65").unwrap();
        assert_eq!(
            (zensical.product_id.as_str(), zensical.version.as_deref()),
            ("zensical", Some("0.0.65"))
        );
        assert!(detect("<p>plain page</p>", Kind::Page).is_empty());
    }

    #[test]
    fn asset_urls_name_packages_versions_and_build_directories() {
        let samples: &[(&str, &str, Option<&str>)] = &[
            ("https://cdn.example.com/npm/vue@3.4.21/dist/vue.global.prod.js", "vue", Some("3.4.21")),
            ("https://unpkg.example.com/react-dom@18.2.0/umd/react-dom.production.min.js", "react", Some("18.2.0")),
            ("https://cdn.example.com/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js", "popper", Some("2.11.8")),
            ("https://cdn.example.com/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css", "bootstrap", Some("5.3.2")),
            ("https://cdn.example.com/npm/htmx.org@latest", "htmx", None),
            ("https://cdnjs.example.com/ajax/libs/lodash.js/4.17.21/lodash.min.js", "lodash", Some("4.17.21")),
            ("https://ajax.example.com/ajax/libs/angularjs/1.8.2/angular.min.js", "angularjs", Some("1.8.2")),
            ("https://ajax.example.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js", "jquery_ui", Some("1.13.2")),
            ("https://code.example.com/jquery-3.7.1.slim.min.js", "jquery", Some("3.7.1")),
            ("https://code.example.com/ui/1.13.2/jquery-ui.js", "jquery_ui", Some("1.13.2")),
            ("https://example.com/js/jquery-3.6.0.min.js", "jquery", Some("3.6.0")),
            ("https://example.com/js/jquery-ui-1.12.1.min.js", "jquery_ui", Some("1.12.1")),
            ("https://example.com/static/angular-1.8.2.min.js?v=1", "angularjs", Some("1.8.2")),
            ("https://example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1", "jquery", Some("3.7.1")),
            ("https://example.com/wp-includes/css/dist/block-library/style.min.css?ver=6.5.2", "wordpress", Some("6.5.2")),
            ("https://example.com/wp-content/themes/twentyone/style.css", "wordpress", None),
            ("https://example.com/_next/static/chunks/main-app-abc.js", "next_js", None),
            ("https://example.com/_nuxt/entry.4f2a.js", "nuxt", None),
            ("https://example.com/_app/immutable/entry/start.js", "sveltekit", None),
            ("https://example.com/_astro/hoisted.js", "astro", None),
            ("https://example.com/webpack-runtime-3f2a9c1b.js", "gatsby", None),
            ("https://example.com/build/entry.client-ABC123.js", "remix", None),
            ("https://example.com/sites/default/files/js/js_abc.js", "drupal", None),
            ("https://example.com/static/version1700000000/frontend/Magento/luma/en_US/requirejs/require.js", "magento", None),
            ("https://cdn.shopify.com/s/files/1/theme.js", "shopify", None),
            ("https://static.parastorage.com/services/wix-thunderbolt/dist/main.js", "wix", None),
            ("https://assets.squarespace.com/universal/scripts-compressed/common.js", "squarespace", None),
            ("https://example.com/lib/slick/slick.min.js", "slick", None),
            ("https://cdn.example.com/npm/slick-carousel@1.8.1/slick/slick.min.js", "slick", Some("1.8.1")),
            ("https://example.com/js/aos.js", "aos", None),
            ("https://html5shim.example.com/svn/trunk/html5.js", "html5shiv", None),
            ("https://example.com/js/html5shiv.min.js", "html5shiv", None),
            ("https://example.com/js/respond.min.js", "respond_js", None),
            ("https://example.com/js/jquery.fullpage.min.js", "fullpage_js", None),
            ("https://example.com/vendor/ScrollMagic.min.js", "scrollmagic", None),
            ("https://example.com/js/jquery.mCustomScrollbar.concat.min.js", "mcustomscrollbar", None),
            ("https://example.com/netfunnel/netfunnel.js", "netfunnel", None),
            ("https://wcs.naver.net/wcslog.js", "naver_analytics", None),
            ("https://example.com/js/moment.min.js", "moment", None),
            ("https://cdn.cookielaw.org/scripttemplates/otSDKStub.js", "onetrust", None),
            ("https://static.cloudflareinsights.com/beacon.min.js/v8b253dfea2ab4077af8c6f58422dfbfd1689876627854", "cloudflare_insights", None),
            ("https://securepubads.g.doubleclick.net/tag/js/gpt.js", "google_ad_manager", None),
            ("https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-1", "google_adsense", None),
            ("https://www.googleadservices.com/pagead/conversion_async.js", "google_ads", None),
            ("https://translate.google.com/translate_a/element.js?cb=init", "google_translate", None),
            ("https://www.google.com/recaptcha/api.js", "recaptcha", None),
            ("https://app-ab01.marketo.com/js/forms2/js/forms2.min.js", "marketo", None),
            ("https://example.com/etc.clientlibs/clientlibs/granite/jquery.lc-7842899024219bcbdb5e72c946870b79-lc.min.js", "adobe_experience_manager", None),
            ("https://ie7-js.example.com/svn/version/2.1(beta4)/IE9.js", "ie9_js", None),
            ("https://example.com/js/jquery.blockUI.js", "jquery_blockui", None),
            ("https://example.com/js/jquery.cookie.js", "jquery_cookie", None),
            ("https://example.com/js/jquery.simplemodal-1.4.4.js", "simplemodal", Some("1.4.4")),
            ("https://example.com/_lib/jquery.bxslider.min.js", "bxslider", None),
            ("https://example.com/js/jquery.easing.1.3.js", "jquery_easing", Some("1.3")),
            ("https://example.com/js/owl.carousel.min.js", "owl_carousel", None),
            ("https://example.com/js/jquery.form.min.js", "jquery_form", None),
            ("https://static.nid.example.com/js/naveridlogin_js_sdk_2.0.0.js", "naver_login", Some("2.0.0")),
            ("https://example.com/pluginfree/js/nppfs-1.13.0.js", "nprotect", Some("1.13.0")),
            ("https://example.com/livewire/livewire.min.js", "livewire", None),
            ("https://www.googletagmanager.com/gtm.js", "google_tag_manager", None),
            ("https://www.google-analytics.com/analytics.js", "google_analytics", None),
            ("https://example.com/js/jquery.min.js", "jquery", None),
            ("https://example.com/css/jquery-ui.css", "jquery_ui", None),
            ("https://example.com/css/bootstrap.min.css?v=2", "bootstrap", None),
            ("https://example.com/lib/swiper-bundle.min.js", "swiper", None),
            ("https://example.com/css/font-awesome.min.css", "font_awesome", None),
            ("https://kit.fontawesome.com/a1b2c3d4e5.js", "font_awesome", None),
            ("https://example.com/js/highlight.pack.js", "highlight_js", None),
            ("https://example.com/js/require.js", "requirejs", None),
            ("https://cdn.polyfill.io/v3/polyfill.min.js?features=default", "polyfill_io", None),
            ("https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js", "firebase", None),
            ("https://maps.googleapis.com/maps/api/js?callback=init", "google_maps", None),
            ("https://oapi.map.naver.com/openapi/v3/maps.js", "naver_maps", None),
            ("https://apis.google.com/js/platform.js", "google_api_client", None),
            ("https://js.hcaptcha.com/1/api.js", "hcaptcha", None),
            ("https://challenges.cloudflare.com/turnstile/v0/api.js", "cloudflare_turnstile", None),
            ("https://js.stripe.com/v3/", "stripe_js", None),
            ("https://www.paypal.com/sdk/js?client-id=test", "paypal_sdk", None),
            ("https://cdn.iamport.kr/v1/iamport.js", "portone", None),
            ("https://js.tosspayments.com/v2/standard", "toss_payments", None),
            ("https://stdpay.inicis.com/stdjs/INIStdPay.js", "kg_inicis", None),
            ("https://pg-web.nicepay.co.kr/v3/common/js/nicepay-pgweb.js", "nicepay", None),
            ("https://cdn.channel.io/plugin/ch-plugin-web.js", "channel_talk", None),
            ("https://widget.intercom.io/widget/abc123", "intercom", None),
            ("https://static.zdassets.com/ekr/snippet.js?key=x", "zendesk_widget", None),
            ("https://consent.cookiebot.com/uc.js", "cookiebot", None),
            ("https://sdk.privacy-center.org/loader.js", "didomi", None),
            ("https://consent.trustarc.com/notice?domain=example.com", "trustarc", None),
            ("https://app.usercentrics.eu/browser-ui/latest/loader.js", "usercentrics", None),
            ("https://sourcepoint.example.com/wrapperMessagingWithoutDetection.js", "sourcepoint", None),
            ("https://cmp.quantcast.com/choice/abc/example.com/choice.js", "quantcast_choice", None),
            ("https://tags.tiqcdn.com/utag/acme/main/prod/utag.js", "tealium", None),
            ("https://assets.adobedtm.com/abc/launch-def.min.js", "adobe_launch", None),
            ("https://cdn.amplitude.com/libs/analytics-browser-2.11.1-min.js.gz", "amplitude", None),
            ("https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js", "mixpanel", None),
            ("https://cdn.segment.com/analytics.js/v1/abc/analytics.min.js", "segment", None),
            ("https://static.hotjar.com/c/hotjar-123456.js?sv=6", "hotjar", None),
            ("https://www.clarity.ms/tag/abc123", "microsoft_clarity", None),
            ("https://plausible.io/js/script.js", "plausible", None),
            ("https://analytics.example.com/js/pa-Z-QYGvOKHwfKWak0xljXn.js", "plausible", None),
            ("https://example.com/js/fontfaceobserver.js", "fontfaceobserver", None),
            ("https://example.com/s/webcomponents-all-noPatch.js", "webcomponentsjs", None),
            ("https://example.com/s/web-animations-next-lite.min.js", "web_animations_js", None),
            ("https://example.com/matomo.js", "matomo", None),
            ("https://static.chartbeat.com/js/chartbeat_mab.js", "chartbeat", None),
            ("https://s.go-mpulse.net/boomerang/ABCDE-FGHIJ", "akamai_mpulse", None),
            ("https://js-agent.newrelic.com/nr-spa-1.250.0.min.js", "new_relic", None),
            ("https://www.datadoghq-browser-agent.com/us1/v5/datadog-rum.js", "datadog_rum", None),
            ("https://js.hs-scripts.com/123456.js", "hubspot", None),
            ("https://connect.facebook.net/en_US/fbevents.js", "meta_pixel", None),
            ("https://analytics.tiktok.com/i18n/pixel/events.js", "tiktok_pixel", None),
            ("https://snap.licdn.com/li.lms-analytics/insight.min.js", "linkedin_insight", None),
            ("https://static.ads-twitter.com/uwt.js", "x_pixel", None),
            ("https://bat.bing.com/bat.js", "microsoft_uet", None),
            ("https://static.criteo.net/js/ld/publishertag.js", "criteo", None),
            ("https://cdn.taboola.com/libtrc/acme/loader.js", "taboola", None),
            ("https://widgets.outbrain.com/outbrain.js", "outbrain", None),
            ("https://mc.yandex.ru/metrika/tag.js", "yandex_metrica", None),
            ("https://hm.baidu.com/hm.js?abc", "baidu_tongji", None),
            ("https://js.adsrvr.org/up_loader.1.1.0.js", "the_trade_desk", None),
            ("https://ads.pubmatic.com/AdServer/js/pwt/123/456/pwt.js", "pubmatic", None),
            ("https://j.6sc.co/6si.min.js", "sixsense", None),
            ("https://sc-static.net/scevent.min.js", "snap_pixel", None),
            ("https://s.pinimg.com/ct/core.js", "pinterest_tag", None),
            (
                "https://static.klaviyo.com/onsite/js/klaviyo.js?company_id=Ab12Cd",
                "klaviyo",
                None,
            ),
            (
                "https://tag.clearbitscripts.com/v1/example/tags.js",
                "clearbit",
                None,
            ),
            (
                "https://www.example.com/ruxitagentjs_ICA2NVfgqrux_10255221207133004.js",
                "dynatrace_rum",
                None,
            ),
            (
                "https://js-cdn.dynatrace.com/jstag/1624d0f62e6/ruxitagent_D_10255221207133004.js",
                "dynatrace_rum",
                None,
            ),
            (
                "https://cdn.appdynamics.com/adrum/adrum-latest.js",
                "appdynamics_browser",
                None,
            ),
            (
                "https://static.example.com/js/adrum-ext.0123456789abcdef0123456789abcdef.js",
                "appdynamics_browser",
                None,
            ),
            (
                "https://s.yimg.jp/images/listing/tool/cv/ytag.js",
                "yahoo_japan_ads",
                None,
            ),
            (
                "https://media.ethicalads.io/media/client/v1.4.0/ethicalads.min.js",
                "ethicalads",
                None,
            ),
            ("https://se.monetate.net/js/2/a-1/p/example.com/entry.js", "monetate", None),
            ("https://cdn.optimizely.com/js/123456.js", "optimizely", None),
            ("https://dev.visualwebsiteoptimizer.com/j.php?a=1", "vwo", None),
            ("https://gtp.acecounter.com:8080/js/acecounter.js", "acecounter", None),
            ("https://rum.beusable.net/load/b123.js", "beusable", None),
            ("https://static.dable.io/dist/plugin.min.js", "dable", None),
        ];
        for (url, id, version) in samples {
            assert!(
                found(detect_url(url)).contains(&one(id, *version)),
                "{id} {version:?} in {url}: {:?}",
                found(detect_url(url))
            );
        }
        assert_eq!(
            found(detect_url(
                "https://code.example.com/ui/1.13.2/jquery-ui.js"
            )),
            [one("jquery_ui", Some("1.13.2"))],
            "jQuery UI's own URL names only jQuery UI"
        );
        for url in [
            "https://example.com/js/app.min.js",
            "https://cdn.example.com/npm/left-pad@1.3.0/index.js",
            "https://example.com/images/jquery-logo.png",
            "https://example.com/users/jquery@example.com/profile",
            // A site's own scripts that only share a library's word.
            "https://example.com/js/app/bootstrap.js",
            "https://example.com/js/swiper.js",
            "https://example.com/js/required.js",
            "https://example.com/js/jquery-plugins.js",
            "https://example.com/js/highlight.js",
            "https://example.com/js/pa-short.js",
            "https://example.com/js/web-animations-demo.js",
        ] {
            assert!(detect_url(url).is_empty(), "{url}");
        }
    }

    #[test]
    fn a_named_version_fills_a_product_found_without_one() {
        let mut found = Vec::new();
        merge(&mut found, known("vue", None).unwrap());
        merge(&mut found, known("vue", Some("3.4.21")).unwrap());
        merge(&mut found, known("vue", Some("2.7.16")).unwrap());
        assert_eq!(
            found
                .iter()
                .map(|item| item.version.as_deref())
                .collect::<Vec<_>>(),
            [Some("3.4.21")]
        );
        assert!(known("vue", Some("<b>")).unwrap().version.is_none());
    }

    #[test]
    fn a_library_files_own_source_map_is_no_finding() {
        let map = "\n//# sourceMappingURL=x.map";
        let mapped = |body: &str, url: &str| {
            let mut found = detect(body, Kind::Script);
            drop_library_source_map(&mut found, url);
            found.iter().any(|item| item.product_id == "source_map")
        };
        let jquery = format!("/*! jQuery v3.7.1 | (c) OpenJS Foundation */{map}");
        let chart = format!("/*!\n * Chart.js v4.4.0\n */{map}");
        let d3 = format!("// https://d3js.org v7.8.5{map}");
        // The file is the library its banner or its URL names.
        assert!(!mapped(&jquery, "https://example.com/js/jquery.min.js"));
        assert!(!mapped(
            &jquery,
            "https://example.com/js/jquery-3.7.1.min.js?v=2"
        ));
        assert!(!mapped(map, "https://example.com/js/owl.carousel.min.js"));
        assert!(!mapped(&chart, "https://example.com/js/chart.umd.min.js"));
        // A bundle carries libraries under a name of its own, and a build
        // directory names the framework, not the file.
        assert!(mapped(
            &jquery,
            "https://example.com/static/js/main.3f2a1b.js"
        ));
        assert!(mapped(map, "https://example.com/js/common.js"));
        // Thousands of tokens in one file name are read in linear time.
        let long = format!("https://example.com/x/{}js", "a.".repeat(32_000));
        assert!(mapped(&jquery, &long));
        assert!(mapped(&d3, "https://example.com/js/main.d3a1f9.js"));
        assert!(mapped(
            map,
            "https://example.com/_next/static/chunks/pages/index-3f2a.js"
        ));
    }
}
