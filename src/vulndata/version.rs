//! Version comparison that answers only what the written segments decide.
//!
//! A CDN URL such as `jquery@3` serves that line's newest release. Read as
//! 3.0.0 it would match 3.0.0's advisories on a site that loads 3.7.1, so a
//! partial version never stands in for its lowest release: a question its
//! segments cannot settle gets `None`, and `None` matches nothing.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    numbers: Vec<u64>,
    pre: Option<String>,
}

impl Version {
    /// `v1.12.4`, `3.5.0-beta` and `1.0.0.beta.3` read; text with no leading
    /// number does not.
    pub fn parse(text: &str) -> Option<Version> {
        let text = text.trim();
        let text = text.strip_prefix('v').unwrap_or(text);
        let end = text
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(text.len());
        let (head, rest) = text.split_at(end);
        // The dot that ends the digits starts the pre-release, as in 1.0.0.beta.3.
        let head = head.strip_suffix('.').unwrap_or(head);
        let numbers = head
            .split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()?;
        // Build metadata after `+` does not rank a version.
        let rest = rest.split('+').next().unwrap_or_default();
        let pre = rest.strip_prefix(['-', '.']).unwrap_or(rest).to_string();
        Some(Version {
            numbers,
            pre: (!pre.is_empty()).then_some(pre),
        })
    }
}

/// Whether `version` is below `bound`, comparing the version's own segments
/// against the bound padded with zeros.
pub fn below(version: &Version, bound: &Version) -> Option<bool> {
    for (index, number) in version.numbers.iter().enumerate() {
        let limit = bound.numbers.get(index).copied().unwrap_or(0);
        if *number != limit {
            return Some(*number < limit);
        }
    }
    let rest = bound.numbers.get(version.numbers.len()..).unwrap_or(&[]);
    if !rest.is_empty() {
        // Every release a partial version could be is at or above the bound
        // only when what it leaves out is zero there.
        return (version.pre.is_none() && rest.iter().all(|number| *number == 0)).then_some(false);
    }
    // The same numbers: a pre-release ranks below its release.
    Some(match (&version.pre, &bound.pre) {
        (Some(pre), Some(limit)) => pre < limit,
        (Some(_), None) => true,
        (None, _) => false,
    })
}

pub fn at_or_above(version: &Version, bound: &Version) -> Option<bool> {
    below(version, bound).map(|below| !below)
}

/// `at_or_above <= version < below`; one undecided side leaves it undecided
/// unless the other already rules the version out.
pub fn in_range(version: &Version, at_or_above: Option<&Version>, below: &Version) -> Option<bool> {
    let lower = at_or_above.map_or(Some(true), |bound| self::at_or_above(version, bound));
    match (lower, self::below(version, below)) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn parses_versions_and_refuses_text() {
        assert!(Version::parse("").is_none());
        assert!(Version::parse("abc").is_none());
        assert!(Version::parse("v1.12.4").is_some());
        assert_eq!(v("1.0.0.beta.3").pre.as_deref(), Some("beta.3"));
        assert_eq!(v("2.0.0-alpha.1").pre.as_deref(), Some("alpha.1"));
    }

    #[test]
    fn a_partial_version_decides_only_what_its_segments_decide() {
        assert_eq!(below(&v("3.4.1"), &v("3.5.0")), Some(true));
        assert_eq!(below(&v("3.5.0"), &v("3.5.0")), Some(false));
        assert_eq!(below(&v("3"), &v("3.5.0")), None); // jquery@3
        assert_eq!(below(&v("2"), &v("3.5.0")), Some(true));
        assert_eq!(below(&v("4"), &v("3.5.0")), Some(false));
        assert_eq!(below(&v("3.5"), &v("3.5.0")), Some(false));
        assert_eq!(below(&v("3.5"), &v("3.5.2")), None);
        assert_eq!(below(&v("2.4"), &v("2.5.0")), Some(true));
        assert_eq!(at_or_above(&v("3"), &v("3.0.0")), Some(true));
        assert_eq!(at_or_above(&v("3"), &v("3.1.0")), None);
        assert_eq!(at_or_above(&v("1.5.1.2"), &v("1.5.1")), Some(true));
        assert_eq!(
            in_range(&v("3.4.1"), Some(&v("1.0.3")), &v("3.5.0")),
            Some(true)
        );
        assert_eq!(in_range(&v("3"), Some(&v("1.0.3")), &v("3.5.0")), None);
    }

    #[test]
    fn a_pre_release_ranks_below_its_release() {
        assert_eq!(below(&v("3.5.0-beta"), &v("3.5.0")), Some(true));
        assert_eq!(at_or_above(&v("3.5.0"), &v("3.5.0-beta")), Some(true));
    }
}
