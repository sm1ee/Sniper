//! Which retire.js components a product Sniper detects is. A product with no
//! entry gets no advisories.

use super::version::{at_or_above, below, Version};

/// A retire.js component, and the version line of the Sniper product it
/// covers when the product's lines are split between components.
pub struct Component {
    pub name: &'static str,
    pub from: Option<&'static str>,
    pub below: Option<&'static str>,
}

const fn all(name: &'static str) -> Component {
    Component {
        name,
        from: None,
        below: None,
    }
}

/// `three_js` is left out: its revision numbers (`r150`) are not retire.js's
/// `0.150.0`. `react` leaves out `react-is` and `scheduler`, whose version
/// lines differ from React's.
pub const RETIRE: &[(&str, &[Component])] = &[
    ("jquery", &[all("jquery")]),
    (
        "jquery_ui",
        &[
            all("jquery-ui"),
            all("jquery-ui-dialog"),
            all("jquery-ui-tooltip"),
        ],
    ),
    ("jquery_migrate", &[all("jquery-migrate")]),
    ("lodash", &[all("lodash")]),
    ("underscore", &[all("underscore.js")]),
    ("moment", &[all("moment.js")]),
    ("angularjs", &[all("angularjs")]),
    ("angular", &[all("@angular/core")]),
    ("react", &[all("react"), all("react-dom")]),
    ("vue", &[all("vue")]),
    ("svelte", &[all("svelte")]),
    ("ember", &[all("ember")]),
    ("backbone", &[all("backbone.js")]),
    ("knockout", &[all("knockout")]),
    ("bootstrap", &[all("bootstrap")]),
    ("handlebars", &[all("handlebars")]),
    ("dompurify", &[all("DOMPurify")]),
    ("chart_js", &[all("chart.js")]),
    ("highcharts", &[all("highcharts")]),
    ("echarts", &[all("echarts")]),
    ("swiper", &[all("swiper")]),
    ("video_js", &[all("video.js")]),
    ("select2", &[all("select2")]),
    ("pdf_js", &[all("pdf.js")]),
    ("tinymce", &[all("tinyMCE")]),
    (
        "ckeditor",
        &[
            Component {
                name: "ckeditor",
                from: None,
                below: Some("5.0.0"),
            },
            Component {
                name: "ckeditor5",
                from: Some("10.0.0"),
                below: None,
            },
        ],
    ),
    ("quill", &[all("quill")]),
    ("mootools", &[all("mootools")]),
    ("prototype", &[all("prototypejs")]),
    ("next_js", &[all("nextjs")]),
    ("axios", &[all("axios")]),
    ("highlight_js", &[all("highlightjs")]),
];

/// The components whose line holds `version`. A line the version cannot be
/// placed in, such as `ckeditor` 5 against both lines, yields nothing.
pub fn retire_components(product_id: &str, version: &Version) -> Vec<&'static str> {
    let Some((_, components)) = RETIRE.iter().find(|(id, _)| *id == product_id) else {
        return Vec::new();
    };
    let holds = |bound: Option<&str>, test: fn(&Version, &Version) -> Option<bool>| {
        bound.map_or(Some(true), |bound| {
            Version::parse(bound).and_then(|bound| test(version, &bound))
        }) == Some(true)
    };
    components
        .iter()
        .filter(|component| holds(component.from, at_or_above) && holds(component.below, below))
        .map(|component| component.name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn a_product_maps_to_the_components_whose_line_holds_its_version() {
        assert_eq!(
            retire_components("react", &v("18.2.0")),
            ["react", "react-dom"]
        );
        assert_eq!(retire_components("ckeditor", &v("4.22.1")), ["ckeditor"]);
        assert_eq!(retire_components("ckeditor", &v("41.0.0")), ["ckeditor5"]);
        assert_eq!(retire_components("jquery_ui", &v("1.13.2")).len(), 3);
        assert!(retire_components("preact", &v("10.0.0")).is_empty());
    }

    #[test]
    fn every_mapped_id_is_a_product_sniper_detects() {
        for (id, _) in RETIRE {
            assert!(
                crate::service_map_libraries::known(id, None).is_some(),
                "{id}"
            );
        }
    }
}
