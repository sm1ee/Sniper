//! `compare_versions` as Nuclei runs it: hashicorp/go-version versions and
//! constraints. Four hundred community templates gate a CVE on a version
//! range, so the edge cases — missing segments, pre-releases, `~>` — follow
//! go-version rather than semver.

use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    segments: Vec<u64>,
    /// How many segments were written; `~>` keys off it.
    significant: usize,
    prerelease: String,
}

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let text = text.strip_prefix('v').unwrap_or(text);
        let (text, _metadata) = text.split_once('+').unwrap_or((text, ""));
        let numeric_end = text
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(text.len());
        let (numbers, rest) = text.split_at(numeric_end);
        if numbers.is_empty() || numbers.starts_with('.') || numbers.ends_with('.') {
            return None;
        }
        let segments: Vec<u64> = numbers
            .split('.')
            .map(|segment| segment.parse().ok())
            .collect::<Option<_>>()?;
        // go-version takes "1.2.3-beta" and also "1.2.3beta".
        let prerelease = rest.strip_prefix('-').unwrap_or(rest);
        if !prerelease
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'~'))
        {
            return None;
        }
        let significant = segments.len();
        let mut segments = segments;
        // go-version pads to three segments, so 1.2 equals 1.2.0.
        while segments.len() < 3 {
            segments.push(0);
        }
        Some(Self {
            segments,
            significant,
            prerelease: prerelease.to_string(),
        })
    }

    fn compare(&self, other: &Self) -> Ordering {
        let length = self.segments.len().max(other.segments.len());
        for index in 0..length {
            let left = self.segments.get(index).copied().unwrap_or(0);
            let right = other.segments.get(index).copied().unwrap_or(0);
            match left.cmp(&right) {
                Ordering::Equal => {}
                unequal => return unequal,
            }
        }
        compare_prerelease(&self.prerelease, &other.prerelease)
    }

    fn equal_segments(&self, other: &Self) -> bool {
        let length = self.segments.len().max(other.segments.len());
        (0..length).all(|index| {
            self.segments.get(index).copied().unwrap_or(0)
                == other.segments.get(index).copied().unwrap_or(0)
        })
    }
}

/// A release sorts after its pre-releases; pre-releases compare part by part,
/// numbers numerically and before words.
fn compare_prerelease(left: &str, right: &str) -> Ordering {
    match (left.is_empty(), right.is_empty()) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        (false, false) => {}
    }
    let mut left_parts = left.split('.');
    let mut right_parts = right.split('.');
    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(a), Some(b)) => {
                let ordering = match (a.parse::<u64>(), b.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => a.cmp(b),
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operator {
    Equal,
    NotEqual,
    Greater,
    Less,
    GreaterEqual,
    LessEqual,
    Pessimistic,
}

/// A pre-release only meets a constraint on the same release with a
/// pre-release of its own (go-version `prereleaseCheck`).
fn prerelease_check(version: &Version, constraint: &Version) -> bool {
    match (
        !version.prerelease.is_empty(),
        !constraint.prerelease.is_empty(),
    ) {
        (true, true) => version.equal_segments(constraint),
        (true, false) => false,
        _ => true,
    }
}

fn satisfies(version: &Version, operator: Operator, constraint: &Version) -> bool {
    let ordering = version.compare(constraint);
    match operator {
        Operator::Equal => ordering == Ordering::Equal,
        Operator::NotEqual => ordering != Ordering::Equal,
        Operator::Greater => prerelease_check(version, constraint) && ordering == Ordering::Greater,
        Operator::Less => prerelease_check(version, constraint) && ordering == Ordering::Less,
        Operator::GreaterEqual => {
            prerelease_check(version, constraint) && ordering != Ordering::Less
        }
        Operator::LessEqual => {
            prerelease_check(version, constraint) && ordering != Ordering::Greater
        }
        Operator::Pessimistic => {
            if !prerelease_check(version, constraint)
                || (!constraint.prerelease.is_empty() && version.prerelease.is_empty())
                || ordering == Ordering::Less
            {
                return false;
            }
            // ~> 1.2.3 allows 1.2.x; ~> 1.2 allows 1.x: every written
            // segment but the last must match.
            let fixed = constraint.significant.saturating_sub(1);
            (0..fixed).all(|index| {
                version.segments.get(index).copied().unwrap_or(0)
                    == constraint.segments.get(index).copied().unwrap_or(0)
            })
        }
    }
}

fn parse_constraint(text: &str) -> Option<(Operator, Version)> {
    let text = text.trim();
    let (operator, rest) = [
        (">=", Operator::GreaterEqual),
        ("<=", Operator::LessEqual),
        ("!=", Operator::NotEqual),
        ("~>", Operator::Pessimistic),
        ("=", Operator::Equal),
        (">", Operator::Greater),
        ("<", Operator::Less),
    ]
    .into_iter()
    .find_map(|(spelling, operator)| text.strip_prefix(spelling).map(|rest| (operator, rest)))
    .unwrap_or((Operator::Equal, text));
    Some((operator, Version::parse(rest)?))
}

/// True when `version` meets every constraint. Each argument may hold several
/// comma-separated constraints, all of which must hold. None when the version
/// or a constraint cannot be read, which Nuclei reports as an error.
pub fn compare_versions(version: &str, constraints: &[&str]) -> Option<bool> {
    let version = Version::parse(version)?;
    let mut all = true;
    for constraint in constraints.iter().flat_map(|text| text.split(',')) {
        let (operator, against) = parse_constraint(constraint)?;
        all &= satisfies(&version, operator, &against);
    }
    Some(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_go_version() {
        // The documented Nuclei example.
        assert_eq!(
            compare_versions("v1.0.0", &[">v0.0.1", "<v1.0.1"]),
            Some(true)
        );
        assert_eq!(compare_versions("15.2.1118", &["<15.2.2562"]), Some(true));
        assert_eq!(compare_versions("15.2.2562", &["<15.2.2562"]), Some(false));
        assert_eq!(compare_versions("1.2", &["=1.2.0"]), Some(true));
        assert_eq!(
            compare_versions("2.4.49", &[">= 2.4.0, < 2.4.50"]),
            Some(true)
        );
        assert_eq!(
            compare_versions("2.4.50", &[">= 2.4.0, < 2.4.50"]),
            Some(false)
        );
        assert_eq!(compare_versions("5.8.1", &["5.8.1"]), Some(true));
        assert_eq!(compare_versions("1.10.0", &[">1.9.9"]), Some(true));
    }

    #[test]
    fn prereleases_only_meet_their_own_release() {
        assert_eq!(compare_versions("1.2.3-beta", &["<1.2.3"]), Some(false));
        assert_eq!(compare_versions("1.2.3-beta", &["<1.2.3-rc1"]), Some(true));
        assert_eq!(compare_versions("1.2.3-beta", &["!=1.2.3"]), Some(true));
        assert_eq!(compare_versions("1.2.3", &[">1.2.3-rc1"]), Some(true));
        assert_eq!(
            compare_versions("1.2.3-alpha.2", &[">1.2.3-alpha.10"]),
            Some(false)
        );
    }

    #[test]
    fn pessimistic_keeps_all_but_the_last_written_segment() {
        assert_eq!(compare_versions("1.2.9", &["~>1.2.3"]), Some(true));
        assert_eq!(compare_versions("1.3.0", &["~>1.2.3"]), Some(false));
        assert_eq!(compare_versions("1.9.0", &["~>1.2"]), Some(true));
        assert_eq!(compare_versions("2.0.0", &["~>1.2"]), Some(false));
        assert_eq!(compare_versions("1.2.2", &["~>1.2.3"]), Some(false));
    }

    #[test]
    fn unreadable_input_is_an_error() {
        assert_eq!(compare_versions("", &["<1"]), None);
        assert_eq!(compare_versions("abc", &["<1"]), None);
        assert_eq!(compare_versions("1.2", &["< x"]), None);
        assert_eq!(compare_versions("1..2", &["<1"]), None);
    }
}
