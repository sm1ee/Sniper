//! The part of Nuclei's `flow:` that templates use without scripting: calls
//! of the template's HTTP blocks joined by `&&` and `||`, such as
//! `http(1) && http(2)`. Nuclei runs a flow as JavaScript; Sniper reads only
//! this subset, and any other flow fails to compile, so its template is
//! listed as unsupported rather than run some other way.

use super::dsl::CompileError;
use super::engine::reason;

/// One step of a compiled flow. A run follows the steps in order with one
/// status, so `&&` and `||` stop as JavaScript's do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Runs these blocks in order. The status becomes whether any of them
    /// matched.
    Run(Vec<usize>),
    /// Jumps to the step when the status is the flag: `false` ends an `&&`,
    /// `true` an `||`.
    SkipIf(bool, usize),
}

/// Parentheses nest at most this deep; a template is untrusted input.
const MAX_DEPTH: usize = 32;

/// Compiles a flow for a template whose blocks carry these ids.
pub fn compile(source: &str, ids: &[Option<String>]) -> Result<Vec<Step>, CompileError> {
    let mut parser = Parser {
        tokens: tokenize(source)?,
        at: 0,
        depth: 0,
        ids,
        steps: Vec::new(),
    };
    parser.any()?;
    if parser.at != parser.tokens.len() {
        return Err(reason("flow"));
    }
    Ok(parser.steps)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Http,
    Open,
    Close,
    Comma,
    And,
    Or,
    /// A number or a string, which names a block by its id or its position.
    Key(String),
}

fn tokenize(source: &str) -> Result<Vec<Token>, CompileError> {
    let mut tokens = Vec::new();
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        let token = match c {
            c if c.is_whitespace() => continue,
            '(' => Token::Open,
            ')' => Token::Close,
            ',' => Token::Comma,
            '&' if chars.next_if_eq(&'&').is_some() => Token::And,
            '|' if chars.next_if_eq(&'|').is_some() => Token::Or,
            '"' | '\'' => {
                let mut key = String::new();
                loop {
                    match chars.next() {
                        Some(end) if end == c => break,
                        Some('\\') | None => return Err(reason("flow")),
                        Some(other) => key.push(other),
                    }
                }
                Token::Key(key)
            }
            '0'..='9' => {
                let mut digits = c.to_string();
                while let Some(digit) = chars.next_if(char::is_ascii_digit) {
                    digits.push(digit);
                }
                // The key is the number as JavaScript prints it: `01` is 1.
                let number: usize = digits.parse().map_err(|_| reason("flow"))?;
                Token::Key(number.to_string())
            }
            c if c.is_ascii_alphabetic() => {
                let mut word = c.to_string();
                while let Some(next) = chars.next_if(|c| c.is_ascii_alphanumeric() || *c == '_') {
                    word.push(next);
                }
                if word != "http" {
                    return Err(reason("flow"));
                }
                Token::Http
            }
            _ => return Err(reason("flow")),
        };
        tokens.push(token);
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
    ids: &'a [Option<String>],
    steps: Vec<Step>,
}

impl Parser<'_> {
    fn eat(&mut self, token: &Token) -> bool {
        let found = self.tokens.get(self.at) == Some(token);
        if found {
            self.at += 1;
        }
        found
    }

    fn expect(&mut self, token: &Token) -> Result<(), CompileError> {
        if self.eat(token) {
            Ok(())
        } else {
            Err(reason("flow"))
        }
    }

    /// `a || b`, which stops at the first true.
    fn any(&mut self) -> Result<(), CompileError> {
        self.joined(&Token::Or, true, Self::all)
    }

    /// `a && b`, which stops at the first false.
    fn all(&mut self) -> Result<(), CompileError> {
        self.joined(&Token::And, false, Self::call)
    }

    fn joined(
        &mut self,
        join: &Token,
        stop: bool,
        part: fn(&mut Self) -> Result<(), CompileError>,
    ) -> Result<(), CompileError> {
        part(self)?;
        let mut skips = Vec::new();
        while self.eat(join) {
            skips.push(self.steps.len());
            self.steps.push(Step::SkipIf(stop, 0));
            part(self)?;
        }
        let end = self.steps.len();
        for skip in skips {
            self.steps[skip] = Step::SkipIf(stop, end);
        }
        Ok(())
    }

    /// `http(…)`, or an expression in parentheses.
    fn call(&mut self) -> Result<(), CompileError> {
        if self.eat(&Token::Open) {
            self.depth += 1;
            if self.depth > MAX_DEPTH {
                return Err(reason("flow"));
            }
            self.any()?;
            self.depth -= 1;
            return self.expect(&Token::Close);
        }
        self.expect(&Token::Http)?;
        self.expect(&Token::Open)?;
        let mut keys = Vec::new();
        if !self.eat(&Token::Close) {
            loop {
                let Some(Token::Key(key)) = self.tokens.get(self.at) else {
                    return Err(reason("flow"));
                };
                keys.push(key.clone());
                self.at += 1;
                if self.eat(&Token::Close) {
                    break;
                }
                self.expect(&Token::Comma)?;
            }
        }
        let blocks = if keys.is_empty() {
            (0..self.ids.len()).collect()
        } else {
            // Nuclei ends a call at a key that names no block.
            keys.iter().map_while(|key| self.block(key)).collect()
        };
        self.steps.push(Step::Run(blocks));
        Ok(())
    }

    /// The block a key names, as Nuclei's map of blocks has it: its id or
    /// its position from 1, a later block taking a key two blocks share.
    fn block(&self, key: &str) -> Option<usize> {
        let mut found = None;
        for (index, id) in self.ids.iter().enumerate() {
            if id.as_deref() == Some(key) || (index + 1).to_string() == key {
                found = Some(index);
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steps(source: &str, ids: &[Option<&str>]) -> Vec<Step> {
        let ids: Vec<Option<String>> = ids.iter().map(|id| id.map(str::to_string)).collect();
        compile(source, &ids).unwrap_or_else(|error| panic!("{source}: {error:?}"))
    }

    #[test]
    fn calls_joined_by_and_and_or_stop_as_javascript_does() {
        let three = [None, None, None];
        assert_eq!(
            steps("http(1) && http(2)", &three),
            [
                Step::Run(vec![0]),
                Step::SkipIf(false, 3),
                Step::Run(vec![1])
            ]
        );
        // `&&` binds tighter than `||`.
        assert_eq!(
            steps("http(1) || http(2) && http(3)", &three),
            [
                Step::Run(vec![0]),
                Step::SkipIf(true, 5),
                Step::Run(vec![1]),
                Step::SkipIf(false, 5),
                Step::Run(vec![2]),
            ]
        );
        assert_eq!(
            steps("http(1) && (http(2) || http(3))", &three),
            [
                Step::Run(vec![0]),
                Step::SkipIf(false, 5),
                Step::Run(vec![1]),
                Step::SkipIf(true, 5),
                Step::Run(vec![2]),
            ]
        );
        // A call without an argument runs every block.
        assert_eq!(
            steps("\n  http( 2 )\n  &&\n  http()\n", &three),
            [
                Step::Run(vec![1]),
                Step::SkipIf(false, 3),
                Step::Run(vec![0, 1, 2]),
            ]
        );
    }

    #[test]
    fn calls_find_blocks_as_nuclei_does() {
        let ids = [None, Some("login"), None];
        // By id, or by number from 1, written as a string or not.
        assert_eq!(
            steps("http(\"login\") && http('3')", &ids),
            [
                Step::Run(vec![1]),
                Step::SkipIf(false, 3),
                Step::Run(vec![2])
            ]
        );
        assert_eq!(steps("http(1, 'login')", &ids), [Step::Run(vec![0, 1])]);
        // A call that names no block stops there and is false.
        assert_eq!(
            steps("http(4) || http(1, 'nope', 2)", &ids),
            [Step::Run(vec![]), Step::SkipIf(true, 3), Step::Run(vec![0])]
        );
    }

    #[test]
    fn any_other_flow_is_a_script_and_is_not_read() {
        for source in [
            "",
            "http(1) & http(2)",
            "!http(1)",
            "http(1);",
            "http(1) &&",
            "(http(1)",
            "http(\"a\\\"b\")",
            "set('a', 1) && http(1)",
            "for (let x of iterate(template.urls)) { http(1) }",
            "dns() && http()",
        ] {
            assert_eq!(compile(source, &[None]).unwrap_err().0, "flow", "{source}");
        }
        let deep = format!("{}http(1){}", "(".repeat(100), ")".repeat(100));
        assert_eq!(compile(&deep, &[None]).unwrap_err().0, "flow");
    }
}
