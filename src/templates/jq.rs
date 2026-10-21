//! The part of jq that Nuclei's `json` extractors use; Nuclei runs them with
//! gojq. Paths (`.a.b`, `."a-b"`, `.[0]`, `.[-1]`, `.[]`, `?`), `|`, `,`,
//! `//`, `and`, `or`, comparisons, `+` and `-`, literals, and the builtins
//! `select`, `contains`, `has`, `first`, `tostring`, `length`, `keys`, `not`
//! and `empty`. Anything else fails to compile, so its template is listed as
//! unsupported rather than read some other way.

use std::cmp::Ordering;

use serde_json::Value;

use super::dsl::CompileError;
use super::engine::reason;

const MAX_QUERY: usize = 4096;
/// Outputs one query may give; the rest are dropped.
const MAX_OUTPUTS: usize = 1000;

/// A compiled `json` extractor query.
#[derive(Clone, Debug)]
pub struct Query(Expr);

impl Query {
    pub fn compile(source: &str) -> Result<Self, CompileError> {
        if source.len() > MAX_QUERY {
            return Err(reason("jq:too_long"));
        }
        let tokens = tokenize(source)?;
        let mut parser = Parser { tokens, at: 0 };
        let expr = parser.pipe()?;
        if parser.at != parser.tokens.len() {
            return Err(reason("jq:syntax"));
        }
        Ok(Self(expr))
    }

    /// The query's outputs on `input` as Nuclei writes them: strings as they
    /// are, numbers without an exponent, `null` as nothing, arrays and
    /// objects as JSON. An error ends the outputs, as it ends Nuclei's.
    pub fn extract(&self, input: &Value) -> Vec<String> {
        let mut outputs = Vec::new();
        let _ = each(&self.0, input, &mut |value| {
            outputs.push(text(&value));
            if outputs.len() >= MAX_OUTPUTS {
                Err(Halt::Stopped)
            } else {
                Ok(())
            }
        });
        outputs
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.as_f64().map(|n| n.to_string()).unwrap_or_default(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => String::new(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

// ---- Syntax ----

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Dot,
    /// `.name`
    Field(String),
    Str(String),
    Num(f64),
    Ident(String),
    Op(&'static str),
}

const OPERATORS: &[&str] = &[
    "//", "==", "!=", "<=", ">=", "<", ">", "|", ",", "+", "-", "(", ")", "[", "]", "?", ";",
];

fn tokenize(source: &str) -> Result<Vec<Token>, CompileError> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    let identifier = |from: usize| {
        let mut end = from;
        while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
            end += 1;
        }
        end
    };
    while at < chars.len() {
        let c = chars[at];
        if c.is_whitespace() {
            at += 1;
        } else if c == '.' {
            match chars.get(at + 1) {
                Some('.') => return Err(reason("jq:recurse")),
                Some(next) if next.is_ascii_alphabetic() || *next == '_' => {
                    let end = identifier(at + 1);
                    tokens.push(Token::Field(chars[at + 1..end].iter().collect()));
                    at = end;
                }
                Some(next) if next.is_ascii_digit() => {
                    return Err(reason("jq:syntax"));
                }
                _ => {
                    tokens.push(Token::Dot);
                    at += 1;
                }
            }
        } else if c == '"' {
            let mut text = String::new();
            at += 1;
            loop {
                match chars.get(at) {
                    None => return Err(reason("jq:unterminated_string")),
                    Some('"') => break,
                    Some('\\') => {
                        let escaped = match chars.get(at + 1) {
                            Some('"') => '"',
                            Some('\\') => '\\',
                            Some('/') => '/',
                            Some('n') => '\n',
                            Some('t') => '\t',
                            Some('r') => '\r',
                            // `\(…)` interpolates; unicode escapes are rare.
                            _ => return Err(reason("jq:escape")),
                        };
                        text.push(escaped);
                        at += 2;
                    }
                    Some(c) => {
                        text.push(*c);
                        at += 1;
                    }
                }
            }
            tokens.push(Token::Str(text));
            at += 1;
        } else if c.is_ascii_digit() {
            let mut end = at;
            while end < chars.len() && (chars[end].is_ascii_digit() || chars[end] == '.') {
                end += 1;
            }
            let number: String = chars[at..end].iter().collect();
            tokens.push(Token::Num(number.parse().map_err(|_| reason("jq:number"))?));
            at = end;
        } else if c.is_ascii_alphabetic() || c == '_' {
            let end = identifier(at);
            tokens.push(Token::Ident(chars[at..end].iter().collect()));
            at = end;
        } else {
            let rest: String = chars[at..chars.len().min(at + 2)].iter().collect();
            let Some(op) = OPERATORS.iter().find(|op| rest.starts_with(**op)) else {
                return Err(reason("jq:syntax"));
            };
            tokens.push(Token::Op(op));
            at += op.len();
        }
    }
    Ok(tokens)
}

#[derive(Clone, Debug)]
enum Expr {
    Identity,
    Literal(Value),
    /// `base[key]` and `.key`: an object's field or an array's element.
    Index(Box<Expr>, Box<Expr>),
    /// `base[]`: every element or value.
    Iterate(Box<Expr>),
    /// `base?`: an error in it ends its outputs quietly.
    Try(Box<Expr>),
    Pipe(Box<Expr>, Box<Expr>),
    Comma(Box<Expr>, Box<Expr>),
    Alternative(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Compare(Ordered, Box<Expr>, Box<Expr>),
    Add(Box<Expr>, Box<Expr>),
    Subtract(Box<Expr>, Box<Expr>),
    Select(Box<Expr>),
    Contains(Box<Expr>),
    Has(Box<Expr>),
    First(Box<Expr>),
    ToString,
    Length,
    Keys,
    Not,
    Empty,
}

#[derive(Clone, Copy, Debug)]
enum Ordered {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn eat(&mut self, op: &str) -> bool {
        if matches!(self.peek(), Some(Token::Op(found)) if *found == op) {
            self.at += 1;
            return true;
        }
        false
    }

    fn eat_word(&mut self, word: &str) -> bool {
        if matches!(self.peek(), Some(Token::Ident(found)) if found == word) {
            self.at += 1;
            return true;
        }
        false
    }

    fn expect(&mut self, op: &str) -> Result<(), CompileError> {
        if self.eat(op) {
            Ok(())
        } else {
            Err(reason("jq:syntax"))
        }
    }

    fn pipe(&mut self) -> Result<Expr, CompileError> {
        let left = self.comma()?;
        if self.eat("|") {
            return Ok(Expr::Pipe(Box::new(left), Box::new(self.pipe()?)));
        }
        Ok(left)
    }

    fn comma(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.alternative()?;
        while self.eat(",") {
            left = Expr::Comma(Box::new(left), Box::new(self.alternative()?));
        }
        Ok(left)
    }

    fn alternative(&mut self) -> Result<Expr, CompileError> {
        let left = self.or()?;
        if self.eat("//") {
            return Ok(Expr::Alternative(
                Box::new(left),
                Box::new(self.alternative()?),
            ));
        }
        Ok(left)
    }

    fn or(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.and()?;
        while self.eat_word("or") {
            left = Expr::Or(Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.compare()?;
        while self.eat_word("and") {
            left = Expr::And(Box::new(left), Box::new(self.compare()?));
        }
        Ok(left)
    }

    fn compare(&mut self) -> Result<Expr, CompileError> {
        let left = self.additive()?;
        let ordered = match self.peek() {
            Some(Token::Op("==")) => Ordered::Eq,
            Some(Token::Op("!=")) => Ordered::Ne,
            Some(Token::Op("<")) => Ordered::Lt,
            Some(Token::Op("<=")) => Ordered::Le,
            Some(Token::Op(">")) => Ordered::Gt,
            Some(Token::Op(">=")) => Ordered::Ge,
            _ => return Ok(left),
        };
        self.at += 1;
        Ok(Expr::Compare(
            ordered,
            Box::new(left),
            Box::new(self.additive()?),
        ))
    }

    fn additive(&mut self) -> Result<Expr, CompileError> {
        let mut left = self.postfix()?;
        loop {
            if self.eat("+") {
                left = Expr::Add(Box::new(left), Box::new(self.postfix()?));
            } else if self.eat("-") {
                left = Expr::Subtract(Box::new(left), Box::new(self.postfix()?));
            } else {
                return Ok(left);
            }
        }
    }

    fn postfix(&mut self) -> Result<Expr, CompileError> {
        let mut expr = self.primary()?;
        loop {
            match self.peek().cloned() {
                Some(Token::Field(name)) => {
                    self.at += 1;
                    expr =
                        Expr::Index(Box::new(expr), Box::new(Expr::Literal(Value::String(name))));
                }
                Some(Token::Dot) => {
                    self.at += 1;
                    match self.peek().cloned() {
                        Some(Token::Str(name)) => {
                            self.at += 1;
                            expr = Expr::Index(
                                Box::new(expr),
                                Box::new(Expr::Literal(Value::String(name))),
                            );
                        }
                        Some(Token::Op("[")) => expr = self.bracket(expr)?,
                        _ => return Err(reason("jq:syntax")),
                    }
                }
                Some(Token::Op("[")) => expr = self.bracket(expr)?,
                Some(Token::Op("?")) => {
                    self.at += 1;
                    expr = Expr::Try(Box::new(expr));
                }
                _ => return Ok(expr),
            }
        }
    }

    /// `[]` or `[key]` after `base`; the next token is `[`.
    fn bracket(&mut self, base: Expr) -> Result<Expr, CompileError> {
        self.expect("[")?;
        if self.eat("]") {
            return Ok(Expr::Iterate(Box::new(base)));
        }
        let key = self.pipe()?;
        self.expect("]")?;
        Ok(Expr::Index(Box::new(base), Box::new(key)))
    }

    fn primary(&mut self) -> Result<Expr, CompileError> {
        let Some(token) = self.peek().cloned() else {
            return Err(reason("jq:syntax"));
        };
        self.at += 1;
        Ok(match token {
            Token::Dot => match self.peek().cloned() {
                Some(Token::Str(name)) => {
                    self.at += 1;
                    Expr::Index(
                        Box::new(Expr::Identity),
                        Box::new(Expr::Literal(Value::String(name))),
                    )
                }
                Some(Token::Op("[")) => self.bracket(Expr::Identity)?,
                _ => Expr::Identity,
            },
            Token::Field(name) => Expr::Index(
                Box::new(Expr::Identity),
                Box::new(Expr::Literal(Value::String(name))),
            ),
            Token::Str(text) => Expr::Literal(Value::String(text)),
            Token::Num(number) => Expr::Literal(
                serde_json::Number::from_f64(number)
                    .map(Value::Number)
                    .ok_or_else(|| reason("jq:number"))?,
            ),
            Token::Op("(") => {
                let inner = self.pipe()?;
                self.expect(")")?;
                inner
            }
            Token::Op("-") => match self.peek().cloned() {
                Some(Token::Num(number)) => {
                    self.at += 1;
                    Expr::Literal(
                        serde_json::Number::from_f64(-number)
                            .map(Value::Number)
                            .ok_or_else(|| reason("jq:number"))?,
                    )
                }
                _ => return Err(reason("jq:syntax")),
            },
            Token::Ident(name) => self.call(&name)?,
            _ => return Err(reason("jq:syntax")),
        })
    }

    fn call(&mut self, name: &str) -> Result<Expr, CompileError> {
        let with_argument = |parser: &mut Self| -> Result<Box<Expr>, CompileError> {
            parser.expect("(")?;
            let argument = parser.pipe()?;
            parser.expect(")")?;
            Ok(Box::new(argument))
        };
        Ok(match name {
            "true" => Expr::Literal(Value::Bool(true)),
            "false" => Expr::Literal(Value::Bool(false)),
            "null" => Expr::Literal(Value::Null),
            "select" => Expr::Select(with_argument(self)?),
            "contains" => Expr::Contains(with_argument(self)?),
            "has" => Expr::Has(with_argument(self)?),
            "first" => Expr::First(with_argument(self)?),
            "tostring" => Expr::ToString,
            "length" => Expr::Length,
            "keys" => Expr::Keys,
            "not" => Expr::Not,
            "empty" => Expr::Empty,
            other => return Err(reason(format!("jq:fn:{other}"))),
        })
    }
}

// ---- Running ----

/// Why a query stopped giving outputs.
#[derive(Debug)]
enum Halt {
    Failed,
    /// Nothing went wrong; no more outputs are wanted.
    Stopped,
}

type Emit<'e> = dyn FnMut(Value) -> Result<(), Halt> + 'e;

fn each(expr: &Expr, input: &Value, emit: &mut Emit<'_>) -> Result<(), Halt> {
    match expr {
        Expr::Identity => emit(input.clone()),
        Expr::Literal(value) => emit(value.clone()),
        Expr::Index(base, key) => {
            let keys = collect(key, input)?;
            each(base, input, &mut |target| {
                for key in &keys {
                    emit(index(&target, key)?)?;
                }
                Ok(())
            })
        }
        Expr::Iterate(base) => each(base, input, &mut |target| match target {
            Value::Array(items) => items.into_iter().try_for_each(&mut *emit),
            Value::Object(fields) => fields.into_iter().try_for_each(|(_, value)| emit(value)),
            _ => Err(Halt::Failed),
        }),
        Expr::Try(inner) => {
            // Only an error inside it is quiet; one further on still counts.
            let mut further = false;
            let result = each(inner, input, &mut |value| {
                emit(value).inspect_err(|_| further = true)
            });
            match result {
                Err(halt) if further => Err(halt),
                _ => Ok(()),
            }
        }
        Expr::Pipe(left, right) => each(left, input, &mut |value| each(right, &value, emit)),
        Expr::Comma(left, right) => {
            each(left, input, emit)?;
            each(right, input, emit)
        }
        Expr::Alternative(left, right) => {
            let mut found = Vec::new();
            let _ = each(left, input, &mut |value| {
                if truthy(&value) {
                    found.push(value);
                }
                Ok(())
            });
            if found.is_empty() {
                return each(right, input, emit);
            }
            found.into_iter().try_for_each(emit)
        }
        Expr::And(left, right) | Expr::Or(left, right) => {
            let and = matches!(expr, Expr::And(..));
            each(left, input, &mut |value| {
                if truthy(&value) != and {
                    return emit(Value::Bool(!and));
                }
                each(right, input, &mut |value| emit(Value::Bool(truthy(&value))))
            })
        }
        Expr::Compare(ordered, left, right) => pairs(left, right, input, emit, |a, b| {
            let ordering = order(a, b);
            Ok(Value::Bool(match ordered {
                Ordered::Eq => ordering == Ordering::Equal,
                Ordered::Ne => ordering != Ordering::Equal,
                Ordered::Lt => ordering == Ordering::Less,
                Ordered::Le => ordering != Ordering::Greater,
                Ordered::Gt => ordering == Ordering::Greater,
                Ordered::Ge => ordering != Ordering::Less,
            }))
        }),
        Expr::Add(left, right) => pairs(left, right, input, emit, add),
        Expr::Subtract(left, right) => pairs(left, right, input, emit, |a, b| match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                number(x.as_f64().unwrap_or(0.0) - y.as_f64().unwrap_or(0.0))
            }
            (Value::Array(x), Value::Array(y)) => Ok(Value::Array(
                x.iter().filter(|item| !y.contains(item)).cloned().collect(),
            )),
            _ => Err(Halt::Failed),
        }),
        Expr::Select(condition) => each(condition, input, &mut |value| {
            if truthy(&value) {
                emit(input.clone())
            } else {
                Ok(())
            }
        }),
        Expr::Contains(other) => each(other, input, &mut |other| {
            emit(Value::Bool(contains(input, &other)?))
        }),
        Expr::Has(key) => each(key, input, &mut |key| {
            emit(Value::Bool(match (input, &key) {
                (Value::Object(fields), Value::String(name)) => fields.contains_key(name),
                (Value::Array(items), Value::Number(at)) => at
                    .as_f64()
                    .is_some_and(|at| at >= 0.0 && (at as usize) < items.len()),
                _ => return Err(Halt::Failed),
            }))
        }),
        Expr::First(inner) => {
            let mut first = None;
            match each(inner, input, &mut |value| {
                first = Some(value);
                Err(Halt::Stopped)
            }) {
                Err(Halt::Failed) => return Err(Halt::Failed),
                _ => {}
            }
            first.map_or(Ok(()), emit)
        }
        Expr::ToString => emit(Value::String(match input {
            Value::String(text) => text.clone(),
            other => serde_json::to_string(other).map_err(|_| Halt::Failed)?,
        })),
        Expr::Length => emit(match input {
            Value::String(text) => Value::from(text.chars().count()),
            Value::Array(items) => Value::from(items.len()),
            Value::Object(fields) => Value::from(fields.len()),
            Value::Null => Value::from(0),
            Value::Number(n) => number(n.as_f64().unwrap_or(0.0).abs())?,
            Value::Bool(_) => return Err(Halt::Failed),
        }),
        Expr::Keys => emit(match input {
            Value::Object(fields) => {
                let mut keys: Vec<&String> = fields.keys().collect();
                keys.sort();
                Value::Array(
                    keys.into_iter()
                        .map(|key| Value::String(key.clone()))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array((0..items.len()).map(Value::from).collect()),
            _ => return Err(Halt::Failed),
        }),
        Expr::Not => emit(Value::Bool(!truthy(input))),
        Expr::Empty => Ok(()),
    }
}

fn collect(expr: &Expr, input: &Value) -> Result<Vec<Value>, Halt> {
    let mut values = Vec::new();
    each(expr, input, &mut |value| {
        values.push(value);
        Ok(())
    })?;
    Ok(values)
}

/// A binary operator over every pair of outputs, the right side's outer, as
/// jq pairs them.
fn pairs(
    left: &Expr,
    right: &Expr,
    input: &Value,
    emit: &mut Emit<'_>,
    op: impl Fn(&Value, &Value) -> Result<Value, Halt>,
) -> Result<(), Halt> {
    let lefts = collect(left, input)?;
    each(right, input, &mut |b| {
        for a in &lefts {
            emit(op(a, &b)?)?;
        }
        Ok(())
    })
}

fn number(value: f64) -> Result<Value, Halt> {
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .ok_or(Halt::Failed)
}

fn index(target: &Value, key: &Value) -> Result<Value, Halt> {
    match (target, key) {
        (Value::Object(fields), Value::String(name)) => {
            Ok(fields.get(name).cloned().unwrap_or(Value::Null))
        }
        (Value::Array(items), Value::Number(at)) => {
            let at = at.as_f64().ok_or(Halt::Failed)?.floor() as i64;
            let at = if at < 0 { items.len() as i64 + at } else { at };
            Ok(usize::try_from(at)
                .ok()
                .and_then(|at| items.get(at))
                .cloned()
                .unwrap_or(Value::Null))
        }
        (Value::Null, Value::String(_) | Value::Number(_)) => Ok(Value::Null),
        _ => Err(Halt::Failed),
    }
}

fn truthy(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
}

fn add(a: &Value, b: &Value) -> Result<Value, Halt> {
    Ok(match (a, b) {
        (Value::Null, other) | (other, Value::Null) => other.clone(),
        (Value::Number(x), Value::Number(y)) => {
            return number(x.as_f64().unwrap_or(0.0) + y.as_f64().unwrap_or(0.0))
        }
        (Value::String(x), Value::String(y)) => Value::String(format!("{x}{y}")),
        (Value::Array(x), Value::Array(y)) => Value::Array(x.iter().chain(y).cloned().collect()),
        (Value::Object(x), Value::Object(y)) => {
            let mut merged = x.clone();
            merged.extend(y.iter().map(|(key, value)| (key.clone(), value.clone())));
            Value::Object(merged)
        }
        _ => return Err(Halt::Failed),
    })
}

/// jq's `contains`: substrings, and the same within arrays and objects.
fn contains(a: &Value, b: &Value) -> Result<bool, Halt> {
    Ok(match (a, b) {
        (Value::String(x), Value::String(y)) => x.contains(y.as_str()),
        (Value::Array(x), Value::Array(y)) => y
            .iter()
            .all(|wanted| x.iter().any(|item| contains(item, wanted).unwrap_or(false))),
        (Value::Object(x), Value::Object(y)) => y.iter().all(|(key, wanted)| {
            x.get(key)
                .is_some_and(|item| contains(item, wanted).unwrap_or(false))
        }),
        _ if std::mem::discriminant(a) == std::mem::discriminant(b) => a == b,
        _ => return Err(Halt::Failed),
    })
}

/// jq's order: null, false, true, numbers, strings, arrays, objects.
fn order(a: &Value, b: &Value) -> Ordering {
    fn rank(value: &Value) -> u8 {
        match value {
            Value::Null => 0,
            Value::Bool(false) => 1,
            Value::Bool(true) => 2,
            Value::Number(_) => 3,
            Value::String(_) => 4,
            Value::Array(_) => 5,
            Value::Object(_) => 6,
        }
    }
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x
            .as_f64()
            .partial_cmp(&y.as_f64())
            .unwrap_or(Ordering::Equal),
        (Value::String(x), Value::String(y)) => x.cmp(y),
        (Value::Array(x), Value::Array(y)) => x
            .iter()
            .zip(y)
            .map(|(a, b)| order(a, b))
            .find(|ordering| *ordering != Ordering::Equal)
            .unwrap_or_else(|| x.len().cmp(&y.len())),
        (Value::Object(x), Value::Object(y)) => {
            let mut xs: Vec<_> = x.iter().collect();
            let mut ys: Vec<_> = y.iter().collect();
            xs.sort_by(|a, b| a.0.cmp(b.0));
            ys.sort_by(|a, b| a.0.cmp(b.0));
            xs.iter()
                .map(|(key, _)| key)
                .cmp(ys.iter().map(|(key, _)| key))
                .then_with(|| {
                    xs.iter()
                        .zip(&ys)
                        .map(|((_, a), (_, b))| order(a, b))
                        .find(|ordering| *ordering != Ordering::Equal)
                        .unwrap_or(Ordering::Equal)
                })
        }
        _ => rank(a).cmp(&rank(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(query: &str, input: &str) -> Vec<String> {
        Query::compile(query)
            .unwrap_or_else(|error| panic!("{query}: {error:?}"))
            .extract(&serde_json::from_str(input).unwrap())
    }

    const DOC: &str = r#"{"a":{"b":[{"c":1},{"c":"x"}]},"d-e":true,"n":null,"v":2.5}"#;

    #[test]
    fn paths_reach_into_objects_and_arrays() {
        assert_eq!(run(".a.b[0].c", DOC), ["1"]);
        assert_eq!(run(".a.b[].c", DOC), ["1", "x"]);
        assert_eq!(run(".a.b[-1].c", DOC), ["x"]);
        assert_eq!(run(r#"."d-e""#, DOC), ["true"]);
        assert_eq!(run(r#".["d-e"]"#, DOC), ["true"]);
        assert_eq!(run(".a.b[1].[]", DOC), ["x"]);
        assert_eq!(run(".v", DOC), ["2.5"]);
        // Nuclei writes null as nothing, and objects as JSON.
        assert_eq!(run(".missing.deeper", DOC), [""]);
        assert_eq!(run(".a", DOC), [r#"{"b":[{"c":1},{"c":"x"}]}"#]);
        // An error ends the outputs; `?` keeps it quiet.
        assert!(run(".a.b[].c.d", DOC).is_empty());
        assert!(run(".a.b[0].c.d?", DOC).is_empty());
        assert_eq!(run(".a.b[].c | .d?, .", DOC), ["1", "x"]);
    }

    #[test]
    fn filters_select_compare_and_combine() {
        let doc = r#"{"items":[{"name":"alpha","tags":["x","admin"],"v":2},{"name":"beta","tags":["y"],"v":3}]}"#;
        assert_eq!(
            run(
                r#".items[] | select(.tags[] | contains("adm")) | .name"#,
                doc
            ),
            ["alpha"]
        );
        assert_eq!(run(r#".items[] | select(.v == 3).name"#, doc), ["beta"]);
        assert_eq!(run(r#".items[] | select(.v != 3) | .name"#, doc), ["alpha"]);
        assert_eq!(run(r#""v" + (.items[0].v | tostring)"#, doc), ["v2"]);
        assert_eq!(run(r#""name: " + .items[1].name"#, doc), ["name: beta"]);
        assert_eq!(
            run(".items[0].name, .items[1].name", doc),
            ["alpha", "beta"]
        );
        assert_eq!(run(r#".missing // "none""#, doc), ["none"]);
        assert_eq!(run("first(.items[] | .name)", doc), ["alpha"]);
        assert_eq!(run(".items | length", doc), ["2"]);
        assert_eq!(run(r#".items[0] | has("tags")"#, doc), ["true"]);
        assert_eq!(run(".items[0].v < .items[1].v and true", doc), ["true"]);
    }

    #[test]
    fn what_it_cannot_read_is_refused() {
        for query in [
            "..|objects",
            "if .a then 1 else 2 end",
            r#"capture("x"; "g")"#,
            ".[",
            r#""\(.a)""#,
            ".a |",
        ] {
            assert!(Query::compile(query).is_err(), "{query}");
        }
    }
}
