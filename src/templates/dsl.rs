//! The expression language of Nuclei templates (`dsl:` matchers and `{{…}}`
//! markers). Nuclei evaluates it with govaluate plus about seventy helper
//! functions; Sniper implements the subset its templates are measured to use,
//! with govaluate's typing: numbers and strings never convert implicitly, a
//! missing variable is an error, and an error makes the expression fail.

use std::{borrow::Cow, sync::Arc};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use regex::Regex;

/// A lexical token. Numbers and strings keep their source spelling until the
/// parser needs their value.
#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    Ident(String),
    Number(String),
    Str(String),
    Op(&'static str),
}

/// Operators longest first, so `==` is not read as `=` `=` and `!~` not as `!`.
const OPERATORS: &[&str] = &[
    "**", "==", "!=", "<=", ">=", "&&", "||", "=~", "!~", "<<", ">>", "<", ">", "!", "+", "-", "*",
    "/", "%", "?", ":", "(", ")", ",", "[", "]", "&", "|", "^", "~",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LexError {
    pub offset: usize,
    pub reason: &'static str,
}

pub fn tokenize(source: &str) -> Result<Vec<Token>, LexError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            let (value, next) = read_string(source, index)?;
            tokens.push(Token::Str(value));
            index = next;
            continue;
        }
        if byte.is_ascii_digit()
            || (byte == b'.' && bytes.get(index + 1).is_some_and(u8::is_ascii_digit))
        {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'.')
            {
                index += 1;
            }
            tokens.push(Token::Number(source[start..index].to_string()));
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            tokens.push(Token::Ident(source[start..index].to_string()));
            continue;
        }
        match OPERATORS
            .iter()
            .find(|operator| source[index..].starts_with(**operator))
        {
            Some(operator) => {
                tokens.push(Token::Op(operator));
                index += operator.len();
            }
            None => {
                return Err(LexError {
                    offset: index,
                    reason: "unexpected_character",
                })
            }
        }
    }
    Ok(tokens)
}

/// Reads a quoted string starting at `start`, returning its unescaped value and
/// the offset after the closing quote. A backslash escapes the next character,
/// as govaluate does; `\n`, `\r` and `\t` mean the control characters.
fn read_string(source: &str, start: usize) -> Result<(String, usize), LexError> {
    let quote = source.as_bytes()[start] as char;
    let mut value = String::new();
    let mut chars = source[start + 1..].char_indices();
    while let Some((offset, character)) = chars.next() {
        match character {
            '\\' => match chars.next() {
                Some((_, 'n')) => value.push('\n'),
                Some((_, 'r')) => value.push('\r'),
                Some((_, 't')) => value.push('\t'),
                Some((_, escaped)) => value.push(escaped),
                None => break,
            },
            c if c == quote => return Ok((value, start + 1 + offset + 1)),
            c => value.push(c),
        }
    }
    Err(LexError {
        offset: start,
        reason: "unterminated_string",
    })
}

/// The functions an expression calls and the bare names it reads, in source
/// order. `true`, `false` and `nil` are literals, `in` an operator.
pub fn names(tokens: &[Token]) -> (Vec<String>, Vec<String>) {
    let mut functions = Vec::new();
    let mut variables = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let Token::Ident(name) = token else { continue };
        if matches!(name.as_str(), "true" | "false" | "nil" | "in") {
            continue;
        }
        if tokens.get(index + 1) == Some(&Token::Op("(")) {
            functions.push(name.clone());
        } else {
            variables.push(name.clone());
        }
    }
    (functions, variables)
}

/// The outermost `{{…}}` markers in a template string, without their braces.
/// Markers nest — `{{url_encode("{{command}}")}}` fills the inner one first —
/// so braces are matched by depth. An unterminated `{{` is not a marker, as
/// in Nuclei.
pub fn markers(text: &str) -> Vec<&str> {
    marker_spans(text)
        .into_iter()
        .map(|(start, end)| text[start + 2..end - 2].trim())
        .collect()
}

/// The text with every marker removed, for reading an expression whose inner
/// markers are filled before it is evaluated.
pub fn without_markers(text: &str) -> String {
    replace_markers(text, "")
}

fn replace_markers(text: &str, with: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    for (start, end) in marker_spans(text) {
        out.push_str(&text[copied..start]);
        out.push_str(with);
        copied = end;
    }
    out.push_str(&text[copied..]);
    out
}

/// Whether an expression names no variable and calls no function, as `7*7`
/// does.
fn names_nothing(expression: &str) -> bool {
    tokenize(expression).is_ok_and(|tokens| {
        let (functions, variables) = names(&tokens);
        functions.is_empty() && variables.is_empty()
    })
}

/// The text with every byte of each marker replaced by `x`. Everything outside
/// the markers keeps its place, so the shape of a raw request can be read
/// before its markers are filled.
pub fn masked(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    for (start, end) in marker_spans(text) {
        bytes[start..end].fill(b'x');
    }
    // Markers start and end with ASCII braces, so whole characters were
    // replaced; an empty result reads as a malformed request.
    String::from_utf8(bytes).unwrap_or_default()
}

/// Byte ranges of the outermost complete markers, braces included.
fn marker_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut index = 0;
    while index + 1 < bytes.len() {
        match &bytes[index..index + 2] {
            b"{{" => {
                if depth == 0 {
                    start = index;
                }
                depth += 1;
                index += 2;
            }
            b"}}" if depth > 0 => {
                depth -= 1;
                index += 2;
                if depth == 0 {
                    spans.push((start, index));
                }
            }
            _ => index += 1,
        }
    }
    spans
}

// ---- Values ----

/// A value an expression produces. Strings borrow from the response they
/// were read from until a function builds a new one.
#[derive(Clone, Debug, PartialEq)]
pub enum Val<'a> {
    Str(Cow<'a, str>),
    Num(f64),
    Bool(bool),
}

impl Val<'_> {
    /// Nuclei's `types.ToString`: whole numbers without a fraction.
    pub fn text(&self) -> Cow<'_, str> {
        match self {
            Val::Str(text) => Cow::Borrowed(text.as_ref()),
            Val::Num(number) => Cow::Owned(format_number(*number)),
            Val::Bool(flag) => Cow::Borrowed(if *flag { "true" } else { "false" }),
        }
    }
}

pub fn format_number(number: f64) -> String {
    if number.is_finite() && number.fract() == 0.0 && number.abs() < 1e15 {
        format!("{}", number as i64)
    } else {
        format!("{number}")
    }
}

/// The variables an expression reads. A name that is not there makes the
/// expression fail, as govaluate's missing parameter does; it never reads as
/// empty, which would turn `!contains(server, …)` true on a missing header.
pub trait Vars {
    fn get(&self, name: &str) -> Option<Val<'_>>;

    /// A value's bytes, where its text would lose some: a binary body.
    fn bytes(&self, _name: &str) -> Option<Cow<'_, [u8]>> {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalError(pub &'static str);

/// Why an expression cannot be compiled: a reason code for the classifier,
/// never the expression text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError(pub String);

impl CompileError {
    fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }
}

/// The longest string an expression may build. Templates hash and compare
/// response text; nothing legitimate comes near this.
const MAX_TEXT: usize = 1024 * 1024;
/// The longest random string a template may ask for.
const MAX_RANDOM_LENGTH: usize = 4096;

// ---- Functions ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuncKind {
    /// Deterministic: usable when judging a response.
    Pure,
    /// Random or time-based: only meaningful while building a request.
    Random,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Func {
    Base64,
    Base64Decode,
    Base64Py,
    CompareVersions,
    DateTime,
    GenerateJwt,
    Mmh3,
    Padding,
    Repeat,
    Substr,
    Concat,
    Contains,
    ContainsAll,
    ContainsAny,
    EndsWith,
    EqualsAny,
    HexDecode,
    HexEncode,
    Join,
    Len,
    LineEndsWith,
    LineStartsWith,
    Md5,
    Regex,
    RegexAll,
    RegexAny,
    Replace,
    ReplaceRegex,
    Reverse,
    Sha1,
    Sha256,
    StartsWith,
    ToLower,
    ToNumber,
    ToString,
    ToUpper,
    Trim,
    TrimLeft,
    TrimPrefix,
    TrimRight,
    TrimSpace,
    TrimSuffix,
    UrlDecode,
    UrlEncode,
    RandBase,
    RandChar,
    RandInt,
    RandTextAlpha,
    RandTextAlphanumeric,
    RandTextNumeric,
    UnixTime,
}

struct FuncSpec {
    name: &'static str,
    func: Func,
    min: usize,
    max: usize,
    kind: FuncKind,
    /// The argument that is a regular expression; it must be a literal so it
    /// compiles once.
    pattern: Option<usize>,
}

const VARIADIC: usize = usize::MAX;

const fn pure(name: &'static str, func: Func, min: usize, max: usize) -> FuncSpec {
    FuncSpec {
        name,
        func,
        min,
        max,
        kind: FuncKind::Pure,
        pattern: None,
    }
}

const fn random(name: &'static str, func: Func, min: usize, max: usize) -> FuncSpec {
    FuncSpec {
        name,
        func,
        min,
        max,
        kind: FuncKind::Random,
        pattern: None,
    }
}

const fn with_pattern(
    name: &'static str,
    func: Func,
    min: usize,
    max: usize,
    at: usize,
) -> FuncSpec {
    FuncSpec {
        name,
        func,
        min,
        max,
        kind: FuncKind::Pure,
        pattern: Some(at),
    }
}

/// The helpers Sniper implements, by Nuclei's documented signatures. Sorted
/// by name. HTML escaping is left out: Go's entity table is not worth
/// approximating for the one template that uses it. Like Nuclei, each is
/// also known by its name without underscores (`tolower`).
const FUNCTIONS: &[FuncSpec] = &[
    pure("base64", Func::Base64, 1, 1),
    pure("base64_decode", Func::Base64Decode, 1, 1),
    pure("base64_py", Func::Base64Py, 1, 1),
    pure("compare_versions", Func::CompareVersions, 2, VARIADIC),
    pure("concat", Func::Concat, 1, VARIADIC),
    pure("contains", Func::Contains, 2, 2),
    pure("contains_all", Func::ContainsAll, 2, VARIADIC),
    pure("contains_any", Func::ContainsAny, 2, VARIADIC),
    random("date_time", Func::DateTime, 1, 2),
    pure("ends_with", Func::EndsWith, 2, VARIADIC),
    pure("equals_any", Func::EqualsAny, 2, VARIADIC),
    // Not the fourth argument, a lifetime counted from now.
    pure("generate_jwt", Func::GenerateJwt, 2, 3),
    pure("hex_decode", Func::HexDecode, 1, 1),
    pure("hex_encode", Func::HexEncode, 1, 1),
    pure("join", Func::Join, 2, VARIADIC),
    pure("len", Func::Len, 1, 1),
    pure("line_ends_with", Func::LineEndsWith, 2, VARIADIC),
    pure("line_starts_with", Func::LineStartsWith, 2, VARIADIC),
    pure("md5", Func::Md5, 1, 1),
    pure("mmh3", Func::Mmh3, 1, 1),
    pure("padding", Func::Padding, 4, 4),
    random("rand_base", Func::RandBase, 1, 2),
    random("rand_char", Func::RandChar, 0, 1),
    random("rand_int", Func::RandInt, 0, 2),
    random("rand_text_alpha", Func::RandTextAlpha, 1, 2),
    random("rand_text_alphanumeric", Func::RandTextAlphanumeric, 1, 2),
    random("rand_text_numeric", Func::RandTextNumeric, 1, 2),
    with_pattern("regex", Func::Regex, 2, 2, 0),
    with_pattern("regex_all", Func::RegexAll, 2, VARIADIC, 0),
    with_pattern("regex_any", Func::RegexAny, 2, VARIADIC, 0),
    pure("repeat", Func::Repeat, 2, 2),
    pure("replace", Func::Replace, 3, 3),
    with_pattern("replace_regex", Func::ReplaceRegex, 3, 3, 1),
    pure("reverse", Func::Reverse, 1, 1),
    pure("sha1", Func::Sha1, 1, 1),
    pure("sha256", Func::Sha256, 1, 1),
    pure("starts_with", Func::StartsWith, 2, VARIADIC),
    pure("substr", Func::Substr, 2, 3),
    pure("to_lower", Func::ToLower, 1, 1),
    pure("to_number", Func::ToNumber, 1, 1),
    pure("to_string", Func::ToString, 1, 1),
    pure("to_upper", Func::ToUpper, 1, 1),
    pure("trim", Func::Trim, 2, 2),
    pure("trim_left", Func::TrimLeft, 2, 2),
    pure("trim_prefix", Func::TrimPrefix, 2, 2),
    pure("trim_right", Func::TrimRight, 2, 2),
    pure("trim_space", Func::TrimSpace, 1, 1),
    pure("trim_suffix", Func::TrimSuffix, 2, 2),
    random("unix_time", Func::UnixTime, 0, 1),
    pure("url_decode", Func::UrlDecode, 1, 1),
    pure("url_encode", Func::UrlEncode, 1, 1),
];

fn spec(name: &str) -> Option<&'static FuncSpec> {
    FUNCTIONS
        .iter()
        .find(|spec| spec.name == name || spec.name.chars().filter(|c| *c != '_').eq(name.chars()))
}

/// Whether Sniper implements a helper, and whether it is deterministic.
pub fn function_kind(name: &str) -> Option<FuncKind> {
    spec(name).map(|spec| spec.kind)
}

// ---- Compiling ----

/// What an expression may use beyond pure functions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Allow {
    /// Random and time helpers, which only make sense when building a request.
    pub random: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arith {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
}

#[derive(Clone, Debug)]
enum Node {
    Lit(Val<'static>),
    Var(String),
    Not(Box<Node>),
    Neg(Box<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Cmp(Cmp, Box<Node>, Box<Node>),
    Arith(Arith, Box<Node>, Box<Node>),
    Match {
        subject: Box<Node>,
        pattern: Arc<Regex>,
        negate: bool,
    },
    Ternary(Box<Node>, Box<Node>, Box<Node>),
    Call {
        func: Func,
        args: Vec<Node>,
        pattern: Option<Arc<Regex>>,
    },
}

/// A compiled expression.
#[derive(Clone, Debug)]
pub struct Expr {
    node: Node,
}

impl Expr {
    pub fn compile(source: &str, allow: Allow) -> Result<Self, CompileError> {
        let tokens =
            tokenize(source).map_err(|error| CompileError::new(format!("dsl:{}", error.reason)))?;
        let mut parser = Parser {
            tokens,
            position: 0,
            allow,
        };
        let node = parser.ternary()?;
        // A token left over is usually an operator Sniper does not evaluate
        // (`in`, bitwise ones); naming it tells the census what to add.
        match parser.peek() {
            None => Ok(Self { node }),
            Some(Token::Op(operator)) => Err(CompileError::new(format!("dsl:operator:{operator}"))),
            Some(Token::Ident(name)) if name == "in" => Err(CompileError::new("dsl:operator:in")),
            Some(_) => Err(CompileError::new("dsl:syntax")),
        }
    }

    pub fn eval<'v>(&self, vars: &'v dyn Vars) -> Result<Val<'v>, EvalError> {
        eval(&self.node, vars)
    }

    /// The variable names the expression reads, for telling which values a
    /// template needs.
    pub fn variables(&self) -> Vec<&str> {
        let mut found = Vec::new();
        collect_variables(&self.node, &mut found);
        found
    }
}

fn collect_variables<'n>(node: &'n Node, found: &mut Vec<&'n str>) {
    match node {
        Node::Lit(_) => {}
        Node::Var(name) => found.push(name),
        Node::Not(inner) | Node::Neg(inner) => collect_variables(inner, found),
        Node::Match { subject, .. } => collect_variables(subject, found),
        Node::And(a, b) | Node::Or(a, b) | Node::Cmp(_, a, b) | Node::Arith(_, a, b) => {
            collect_variables(a, found);
            collect_variables(b, found);
        }
        Node::Ternary(a, b, c) => {
            collect_variables(a, found);
            collect_variables(b, found);
            collect_variables(c, found);
        }
        Node::Call { args, .. } => args.iter().for_each(|arg| collect_variables(arg, found)),
    }
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
    allow: Allow,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn eat(&mut self, operator: &str) -> bool {
        if matches!(self.peek(), Some(Token::Op(op)) if *op == operator) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, operator: &str) -> Result<(), CompileError> {
        if self.eat(operator) {
            Ok(())
        } else {
            Err(CompileError::new("dsl:syntax"))
        }
    }

    fn ternary(&mut self) -> Result<Node, CompileError> {
        let condition = self.or()?;
        if !self.eat("?") {
            return Ok(condition);
        }
        let then = self.ternary()?;
        self.expect(":")?;
        let otherwise = self.ternary()?;
        Ok(Node::Ternary(
            Box::new(condition),
            Box::new(then),
            Box::new(otherwise),
        ))
    }

    fn or(&mut self) -> Result<Node, CompileError> {
        let mut left = self.and()?;
        while self.eat("||") {
            let right = self.and()?;
            left = Node::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Node, CompileError> {
        let mut left = self.comparison()?;
        while self.eat("&&") {
            let right = self.comparison()?;
            left = Node::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn comparison(&mut self) -> Result<Node, CompileError> {
        let mut left = self.additive()?;
        loop {
            let operator = match self.peek() {
                Some(Token::Op(op)) => *op,
                _ => return Ok(left),
            };
            let cmp = match operator {
                "==" => Cmp::Eq,
                "!=" => Cmp::Ne,
                "<" => Cmp::Lt,
                "<=" => Cmp::Le,
                ">" => Cmp::Gt,
                ">=" => Cmp::Ge,
                "=~" | "!~" => {
                    self.position += 1;
                    // A pattern built at run time would compile on every
                    // response; Sniper only takes literal patterns.
                    let Some(Token::Str(pattern)) = self.peek().cloned() else {
                        return Err(CompileError::new("dsl:regex_computed"));
                    };
                    self.position += 1;
                    left = Node::Match {
                        subject: Box::new(left),
                        pattern: Arc::new(go_regex(&pattern)?),
                        negate: operator == "!~",
                    };
                    continue;
                }
                _ => return Ok(left),
            };
            self.position += 1;
            let right = self.additive()?;
            left = Node::Cmp(cmp, Box::new(left), Box::new(right));
        }
    }

    fn additive(&mut self) -> Result<Node, CompileError> {
        let mut left = self.multiplicative()?;
        loop {
            let arith = if self.eat("+") {
                Arith::Add
            } else if self.eat("-") {
                Arith::Sub
            } else {
                return Ok(left);
            };
            let right = self.multiplicative()?;
            left = Node::Arith(arith, Box::new(left), Box::new(right));
        }
    }

    fn multiplicative(&mut self) -> Result<Node, CompileError> {
        let mut left = self.power()?;
        loop {
            let arith = if self.eat("*") {
                Arith::Mul
            } else if self.eat("/") {
                Arith::Div
            } else if self.eat("%") {
                Arith::Mod
            } else {
                return Ok(left);
            };
            let right = self.power()?;
            left = Node::Arith(arith, Box::new(left), Box::new(right));
        }
    }

    fn power(&mut self) -> Result<Node, CompileError> {
        let base = self.unary()?;
        if self.eat("**") {
            let exponent = self.power()?;
            return Ok(Node::Arith(Arith::Pow, Box::new(base), Box::new(exponent)));
        }
        Ok(base)
    }

    fn unary(&mut self) -> Result<Node, CompileError> {
        if self.eat("!") {
            return Ok(Node::Not(Box::new(self.unary()?)));
        }
        if self.eat("-") {
            return Ok(Node::Neg(Box::new(self.unary()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Node, CompileError> {
        let token = self
            .peek()
            .cloned()
            .ok_or_else(|| CompileError::new("dsl:syntax"))?;
        self.position += 1;
        match token {
            Token::Number(spelling) => spelling
                .parse::<f64>()
                .map(|number| Node::Lit(Val::Num(number)))
                .map_err(|_| CompileError::new("dsl:number")),
            Token::Str(text) => Ok(Node::Lit(Val::Str(Cow::Owned(text)))),
            Token::Op("(") => {
                let inner = self.ternary()?;
                self.expect(")")?;
                Ok(inner)
            }
            Token::Op(operator) => Err(CompileError::new(format!("dsl:operator:{operator}"))),
            Token::Ident(name) => match name.as_str() {
                "true" => Ok(Node::Lit(Val::Bool(true))),
                "false" => Ok(Node::Lit(Val::Bool(false))),
                "in" | "nil" => Err(CompileError::new(format!("dsl:operator:{name}"))),
                _ if self.eat("(") => self.call(&name),
                _ => Ok(Node::Var(name)),
            },
        }
    }

    fn call(&mut self, name: &str) -> Result<Node, CompileError> {
        let spec = spec(name).ok_or_else(|| CompileError::new(format!("fn:{name}")))?;
        if spec.kind == FuncKind::Random && !self.allow.random {
            return Err(CompileError::new("randomness"));
        }
        let mut args = Vec::new();
        if !self.eat(")") {
            loop {
                args.push(self.ternary()?);
                if self.eat(")") {
                    break;
                }
                self.expect(",")?;
            }
        }
        if args.len() < spec.min || args.len() > spec.max {
            return Err(CompileError::new(format!("dsl:arity:{name}")));
        }
        let pattern = match spec.pattern {
            Some(index) => match &args[index] {
                Node::Lit(Val::Str(pattern)) => Some(Arc::new(go_regex(pattern)?)),
                _ => return Err(CompileError::new("dsl:regex_computed")),
            },
            None => None,
        };
        Ok(Node::Call {
            func: spec.func,
            args,
            pattern,
        })
    }
}

// ---- Evaluating ----

fn eval<'v>(node: &Node, vars: &'v dyn Vars) -> Result<Val<'v>, EvalError> {
    match node {
        Node::Lit(value) => Ok(value.clone()),
        Node::Var(name) => vars.get(name).ok_or(EvalError("unknown_variable")),
        Node::Not(inner) => Ok(Val::Bool(!boolean(eval(inner, vars)?)?)),
        Node::Neg(inner) => Ok(Val::Num(-number(&eval(inner, vars)?)?)),
        Node::And(a, b) => Ok(Val::Bool(
            boolean(eval(a, vars)?)? && boolean(eval(b, vars)?)?,
        )),
        Node::Or(a, b) => Ok(Val::Bool(
            boolean(eval(a, vars)?)? || boolean(eval(b, vars)?)?,
        )),
        Node::Cmp(cmp, a, b) => compare(*cmp, &eval(a, vars)?, &eval(b, vars)?),
        Node::Arith(arith, a, b) => arithmetic(*arith, eval(a, vars)?, eval(b, vars)?),
        Node::Match {
            subject,
            pattern,
            negate,
        } => {
            let subject = eval(subject, vars)?;
            Ok(Val::Bool(pattern.is_match(&subject.text()) != *negate))
        }
        Node::Ternary(condition, then, otherwise) => {
            if boolean(eval(condition, vars)?)? {
                eval(then, vars)
            } else {
                eval(otherwise, vars)
            }
        }
        Node::Call {
            func,
            args,
            pattern,
        } => {
            // A hash or an encoding of the body reads its bytes, which its
            // text may have lost: a favicon's `mmh3(base64_py(body))`.
            if let [Node::Var(name)] = args.as_slice() {
                if reads_bytes(*func) {
                    if let Some(bytes) = vars.bytes(name) {
                        return call_on_bytes(*func, &bytes);
                    }
                }
            }
            let values = args
                .iter()
                .map(|arg| eval(arg, vars))
                .collect::<Result<Vec<_>, _>>()?;
            call(*func, values, pattern.as_deref())
        }
    }
}

fn boolean(value: Val<'_>) -> Result<bool, EvalError> {
    match value {
        Val::Bool(flag) => Ok(flag),
        _ => Err(EvalError("type")),
    }
}

fn number(value: &Val<'_>) -> Result<f64, EvalError> {
    match value {
        Val::Num(number) => Ok(*number),
        _ => Err(EvalError("type")),
    }
}

/// govaluate: numbers compare as numbers and strings as strings; values of
/// different types are never equal and cannot be ordered.
fn compare<'v>(cmp: Cmp, a: &Val<'_>, b: &Val<'_>) -> Result<Val<'v>, EvalError> {
    use std::cmp::Ordering;
    let ordering: Option<Ordering> = match (a, b) {
        (Val::Num(x), Val::Num(y)) => x.partial_cmp(y),
        (Val::Str(x), Val::Str(y)) => Some(x.as_ref().cmp(y.as_ref())),
        (Val::Bool(x), Val::Bool(y)) => match cmp {
            Cmp::Eq => return Ok(Val::Bool(x == y)),
            Cmp::Ne => return Ok(Val::Bool(x != y)),
            _ => return Err(EvalError("type")),
        },
        _ => match cmp {
            Cmp::Eq => return Ok(Val::Bool(false)),
            Cmp::Ne => return Ok(Val::Bool(true)),
            _ => return Err(EvalError("type")),
        },
    };
    let Some(ordering) = ordering else {
        // NaN: only inequality holds.
        return Ok(Val::Bool(cmp == Cmp::Ne));
    };
    Ok(Val::Bool(match cmp {
        Cmp::Eq => ordering == Ordering::Equal,
        Cmp::Ne => ordering != Ordering::Equal,
        Cmp::Lt => ordering == Ordering::Less,
        Cmp::Le => ordering != Ordering::Greater,
        Cmp::Gt => ordering == Ordering::Greater,
        Cmp::Ge => ordering != Ordering::Less,
    }))
}

/// `+` joins text when either side is a string, as govaluate does.
fn arithmetic<'v>(arith: Arith, a: Val<'_>, b: Val<'_>) -> Result<Val<'v>, EvalError> {
    if arith == Arith::Add && (matches!(a, Val::Str(_)) || matches!(b, Val::Str(_))) {
        if matches!(a, Val::Bool(_)) || matches!(b, Val::Bool(_)) {
            return Err(EvalError("type"));
        }
        let mut text = a.text().into_owned();
        text.push_str(&b.text());
        return owned_text(text);
    }
    let (x, y) = (number(&a)?, number(&b)?);
    Ok(Val::Num(match arith {
        Arith::Add => x + y,
        Arith::Sub => x - y,
        Arith::Mul => x * y,
        Arith::Div => x / y,
        Arith::Mod => x % y,
        Arith::Pow => x.powf(y),
    }))
}

fn owned_text<'v>(text: String) -> Result<Val<'v>, EvalError> {
    if text.len() > MAX_TEXT {
        return Err(EvalError("too_large"));
    }
    Ok(Val::Str(Cow::Owned(text)))
}

fn length_argument(value: &Val<'_>) -> Result<usize, EvalError> {
    let length = match value {
        Val::Num(number) if number.is_finite() && *number >= 0.0 => *number as usize,
        Val::Str(text) => text.trim().parse().map_err(|_| EvalError("type"))?,
        _ => return Err(EvalError("type")),
    };
    if length > MAX_RANDOM_LENGTH {
        return Err(EvalError("too_large"));
    }
    Ok(length)
}

const LETTERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

fn random_from(charset: &str, length: usize) -> Result<String, EvalError> {
    use rand::seq::SliceRandom;
    let characters: Vec<char> = charset.chars().collect();
    if characters.is_empty() {
        return Err(EvalError("empty_charset"));
    }
    let mut rng = rand::thread_rng();
    Ok((0..length)
        .map(|_| *characters.choose(&mut rng).unwrap())
        .collect())
}

/// A `{{randstr}}`: lowercase letters and digits, long enough never to
/// turn up in a response by chance.
pub(crate) fn random_id() -> String {
    random_from("abcdefghijklmnopqrstuvwxyz0123456789", 27).unwrap_or_default()
}

fn without(charset: &str, excluded: &str) -> String {
    charset.chars().filter(|c| !excluded.contains(*c)).collect()
}

/// The helpers that work on bytes: given text, its UTF-8.
fn reads_bytes(func: Func) -> bool {
    matches!(
        func,
        Func::Base64
            | Func::Base64Py
            | Func::HexEncode
            | Func::Len
            | Func::Md5
            | Func::Mmh3
            | Func::Sha1
            | Func::Sha256
    )
}

fn call_on_bytes<'v>(func: Func, bytes: &[u8]) -> Result<Val<'v>, EvalError> {
    use md5::Digest as _;
    match func {
        Func::Base64 => owned_text(STANDARD.encode(bytes)),
        Func::Base64Py => owned_text(base64_py(bytes)),
        Func::HexEncode => owned_text(hex_lower(bytes)),
        Func::Len => Ok(Val::Num(bytes.len() as f64)),
        Func::Md5 => owned_text(hex_lower(&md5::Md5::digest(bytes))),
        // Signed, as Nuclei prints it and Shodan lists favicon hashes.
        Func::Mmh3 => owned_text((murmur3(bytes) as i32).to_string()),
        Func::Sha1 => owned_text(hex_lower(&sha1::Sha1::digest(bytes))),
        Func::Sha256 => owned_text(hex_lower(&rsa::sha2::Sha256::digest(bytes))),
        _ => Err(EvalError("bytes")),
    }
}

/// Python's `base64.encodebytes`, as Nuclei writes it: a line break after
/// every 76 characters and at the end.
fn base64_py(bytes: &[u8]) -> String {
    let encoded = STANDARD.encode(bytes);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 + 1);
    for line in encoded.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    if out.is_empty() {
        out.push('\n');
    }
    out
}

/// MurmurHash3, x86 32-bit, seed 0.
fn murmur3(data: &[u8]) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let scramble = |k: u32| k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
    let mut hash = 0u32;
    let mut blocks = data.chunks_exact(4);
    for block in &mut blocks {
        hash ^= scramble(u32::from_le_bytes([block[0], block[1], block[2], block[3]]));
        hash = hash
            .rotate_left(13)
            .wrapping_mul(5)
            .wrapping_add(0xe654_6b64);
    }
    let tail = blocks.remainder();
    if !tail.is_empty() {
        let k = tail.iter().enumerate().fold(0u32, |k, (index, byte)| {
            k ^ (u32::from(*byte) << (8 * index))
        });
        hash ^= scramble(k);
    }
    hash ^= data.len() as u32;
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x85eb_ca6b);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(0xc2b2_ae35);
    hash ^ (hash >> 16)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    use rsa::sha2::{Digest as _, Sha256};
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |with: u8| block.iter().map(|byte| byte ^ with).collect::<Vec<u8>>();
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .to_vec()
}

/// Nuclei's `generate_jwt` for the HS256 tokens templates sign: the claims
/// in key order, as Go writes a map.
fn generate_jwt(claims: &str, algorithm: &str, key: &str) -> Result<String, EvalError> {
    let Ok(serde_json::Value::Object(claims)) = serde_json::from_str(claims) else {
        return Err(EvalError("jwt_claims"));
    };
    if !algorithm.eq_ignore_ascii_case("HS256") {
        return Err(EvalError("jwt_algorithm"));
    }
    let claims: std::collections::BTreeMap<String, serde_json::Value> =
        claims.into_iter().collect();
    let payload = serde_json::to_vec(&claims).map_err(|_| EvalError("jwt_claims"))?;
    let signing = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = URL_SAFE_NO_PAD.encode(hmac_sha256(key.as_bytes(), signing.as_bytes()));
    Ok(format!("{signing}.{signature}"))
}

/// Nuclei's `date_time` with `%` fields: `%Y` year, `%M` month, `%D` day,
/// `%H` hour, `%m` minute and `%S` second, the year's, day's, hour's and
/// second's in either case, each at least two digits. A format without them
/// is a Go layout, which Sniper does not write.
fn format_date_time(format: &str, at: chrono::NaiveDateTime) -> Result<String, EvalError> {
    use chrono::{Datelike as _, Timelike as _};
    let fields: Vec<char> = format
        .split('%')
        .skip(1)
        .filter_map(|rest| rest.chars().next().filter(char::is_ascii_alphabetic))
        .collect();
    if fields.is_empty() {
        return Err(EvalError("date_layout"));
    }
    let mut out = format.to_string();
    for field in fields {
        let value = match field {
            'Y' | 'y' => at.year(),
            'M' => at.month() as i32,
            'D' | 'd' => at.day() as i32,
            'H' | 'h' => at.hour() as i32,
            'm' => at.minute() as i32,
            'S' | 's' => at.second() as i32,
            _ => return Err(EvalError("date_field")),
        };
        out = out.replace(&format!("%{field}"), &format!("{value:02}"));
    }
    Ok(out)
}

fn call<'v>(func: Func, args: Vec<Val<'v>>, pattern: Option<&Regex>) -> Result<Val<'v>, EvalError> {
    let text = |index: usize| args[index].text();
    let rest_texts = |from: usize| -> Vec<String> {
        args[from..]
            .iter()
            .map(|arg| arg.text().into_owned())
            .collect()
    };
    let value = match func {
        Func::Base64
        | Func::Base64Py
        | Func::HexEncode
        | Func::Len
        | Func::Md5
        | Func::Mmh3
        | Func::Sha1
        | Func::Sha256 => return call_on_bytes(func, text(0).as_bytes()),
        Func::Repeat => {
            let piece = text(0);
            let count: usize = text(1).parse().map_err(|_| EvalError("repeat"))?;
            if piece.len().saturating_mul(count) > MAX_TEXT {
                return Err(EvalError("too_large"));
            }
            return owned_text(piece.repeat(count));
        }
        // Byte offsets into the text, as Go slices a string.
        Func::Substr => {
            let input = text(0);
            let bytes = input.as_bytes();
            let start: usize = text(1).parse().map_err(|_| EvalError("substr"))?;
            let end: usize = match args.get(2) {
                Some(end) => end.text().parse().map_err(|_| EvalError("substr"))?,
                None => bytes.len(),
            };
            if bytes.is_empty() || start > end || end > bytes.len() {
                return Err(EvalError("substr"));
            }
            return owned_text(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        }
        Func::Padding => {
            let length = match &args[2] {
                Val::Num(number) => *number,
                other => other
                    .text()
                    .trim()
                    .parse::<f64>()
                    .map_err(|_| EvalError("padding"))?,
            } as i64;
            let (data, fill) = (text(0), text(1));
            if length == 0 || fill.is_empty() {
                return Err(EvalError("padding"));
            }
            // A longer value is left as it is, not cut.
            if data.len() as i64 >= length {
                return owned_text(data.into_owned());
            }
            if length as usize > MAX_TEXT {
                return Err(EvalError("too_large"));
            }
            let fill: Vec<u8> = fill
                .bytes()
                .cycle()
                .take(length as usize - data.len())
                .collect();
            let padded = match &args[3] {
                Val::Str(mode) if mode == "prefix" => [fill.as_slice(), data.as_bytes()].concat(),
                Val::Str(mode) if mode == "suffix" => [data.as_bytes(), fill.as_slice()].concat(),
                _ => return Err(EvalError("padding")),
            };
            return owned_text(String::from_utf8_lossy(&padded).into_owned());
        }
        Func::GenerateJwt => {
            let key = args
                .get(2)
                .map(|key| key.text().into_owned())
                .unwrap_or_default();
            return owned_text(generate_jwt(&text(0), &text(1), &key)?);
        }
        // The local time, or the Unix time given, as Nuclei's.
        Func::DateTime => {
            use chrono::TimeZone as _;
            let at = match args.get(1) {
                None => chrono::Local::now(),
                Some(value) => {
                    let seconds = match value {
                        Val::Num(number) => *number as i64,
                        other => other.text().trim().parse().map_err(|_| EvalError("time"))?,
                    };
                    chrono::Local
                        .timestamp_opt(seconds, 0)
                        .single()
                        .ok_or(EvalError("time"))?
                }
            };
            return owned_text(format_date_time(&text(0), at.naive_local())?);
        }
        Func::Contains => Val::Bool(text(0).contains(text(1).as_ref())),
        Func::ContainsAll => {
            let haystack = text(0);
            Val::Bool(
                rest_texts(1)
                    .iter()
                    .all(|needle| haystack.contains(needle.as_str())),
            )
        }
        Func::ContainsAny => {
            let haystack = text(0);
            Val::Bool(
                rest_texts(1)
                    .iter()
                    .any(|needle| haystack.contains(needle.as_str())),
            )
        }
        Func::StartsWith => {
            let haystack = text(0);
            Val::Bool(
                rest_texts(1)
                    .iter()
                    .any(|prefix| haystack.starts_with(prefix.as_str())),
            )
        }
        Func::EndsWith => {
            let haystack = text(0);
            Val::Bool(
                rest_texts(1)
                    .iter()
                    .any(|suffix| haystack.ends_with(suffix.as_str())),
            )
        }
        Func::LineStartsWith => {
            let haystack = text(0);
            let prefixes = rest_texts(1);
            Val::Bool(haystack.split('\n').any(|line| {
                prefixes
                    .iter()
                    .any(|prefix| line.starts_with(prefix.as_str()))
            }))
        }
        Func::LineEndsWith => {
            let haystack = text(0);
            let suffixes = rest_texts(1);
            Val::Bool(haystack.split('\n').any(|line| {
                suffixes
                    .iter()
                    .any(|suffix| line.ends_with(suffix.as_str()))
            }))
        }
        Func::EqualsAny => {
            let value = text(0);
            Val::Bool(rest_texts(1).iter().any(|other| other == value.as_ref()))
        }
        Func::Regex => Val::Bool(pattern.ok_or(EvalError("pattern"))?.is_match(&text(1))),
        Func::RegexAll => {
            let pattern = pattern.ok_or(EvalError("pattern"))?;
            Val::Bool(rest_texts(1).iter().all(|input| pattern.is_match(input)))
        }
        Func::RegexAny => {
            let pattern = pattern.ok_or(EvalError("pattern"))?;
            Val::Bool(rest_texts(1).iter().any(|input| pattern.is_match(input)))
        }
        Func::ToLower => return owned_text(text(0).to_lowercase()),
        Func::ToUpper => return owned_text(text(0).to_uppercase()),
        Func::Trim => {
            let cutset = text(1);
            return owned_text(text(0).trim_matches(|c| cutset.contains(c)).to_string());
        }
        Func::TrimLeft => {
            let cutset = text(1);
            return owned_text(
                text(0)
                    .trim_start_matches(|c| cutset.contains(c))
                    .to_string(),
            );
        }
        Func::TrimRight => {
            let cutset = text(1);
            return owned_text(text(0).trim_end_matches(|c| cutset.contains(c)).to_string());
        }
        Func::TrimPrefix => {
            let (input, prefix) = (text(0), text(1));
            return owned_text(
                input
                    .strip_prefix(prefix.as_ref())
                    .unwrap_or(&input)
                    .to_string(),
            );
        }
        Func::TrimSuffix => {
            let (input, suffix) = (text(0), text(1));
            return owned_text(
                input
                    .strip_suffix(suffix.as_ref())
                    .unwrap_or(&input)
                    .to_string(),
            );
        }
        Func::TrimSpace => return owned_text(text(0).trim().to_string()),
        Func::Replace => return owned_text(text(0).replace(text(1).as_ref(), &text(2))),
        Func::ReplaceRegex => {
            let pattern = pattern.ok_or(EvalError("pattern"))?;
            return owned_text(pattern.replace_all(&text(0), text(2).as_ref()).into_owned());
        }
        Func::Concat => return owned_text(rest_texts(0).concat()),
        Func::Join => return owned_text(rest_texts(1).join(&text(0))),
        Func::ToNumber => match &args[0] {
            Val::Num(number) => Val::Num(*number),
            Val::Str(text) => Val::Num(text.trim().parse().map_err(|_| EvalError("type"))?),
            Val::Bool(_) => return Err(EvalError("type")),
        },
        Func::ToString => return owned_text(text(0).into_owned()),
        Func::CompareVersions => {
            let constraints = rest_texts(1);
            let constraints: Vec<&str> = constraints.iter().map(String::as_str).collect();
            Val::Bool(
                super::version::compare_versions(&text(0), &constraints)
                    .ok_or(EvalError("version"))?,
            )
        }
        Func::Base64Decode => {
            let bytes = STANDARD
                .decode(text(0).trim().as_bytes())
                .map_err(|_| EvalError("base64"))?;
            return owned_text(String::from_utf8_lossy(&bytes).into_owned());
        }
        Func::UrlEncode => return owned_text(query_escape(&text(0))),
        Func::UrlDecode => return owned_text(query_unescape(&text(0)).ok_or(EvalError("url"))?),
        Func::HexDecode => {
            let bytes = hex_decode(text(0).trim()).ok_or(EvalError("hex"))?;
            return owned_text(String::from_utf8_lossy(&bytes).into_owned());
        }
        Func::Reverse => return owned_text(text(0).chars().rev().collect()),
        Func::RandBase => {
            let length = length_argument(&args[0])?;
            let charset = match args.get(1) {
                Some(charset) => charset.text().into_owned(),
                None => format!("{LETTERS}{DIGITS}"),
            };
            return owned_text(random_from(&charset, length)?);
        }
        Func::RandChar => {
            let charset = match args.first() {
                Some(charset) => charset.text().into_owned(),
                None => format!("{LETTERS}{DIGITS}"),
            };
            return owned_text(random_from(&charset, 1)?);
        }
        Func::RandTextAlpha | Func::RandTextAlphanumeric | Func::RandTextNumeric => {
            let length = length_argument(&args[0])?;
            let base = match func {
                Func::RandTextAlpha => LETTERS.to_string(),
                Func::RandTextAlphanumeric => format!("{LETTERS}{DIGITS}"),
                _ => DIGITS.to_string(),
            };
            let excluded = args
                .get(1)
                .map(|arg| arg.text().into_owned())
                .unwrap_or_default();
            return owned_text(random_from(&without(&base, &excluded), length)?);
        }
        Func::RandInt => {
            use rand::Rng;
            let min = match args.first() {
                Some(value) => number(value)?,
                None => 0.0,
            };
            let max = match args.get(1) {
                Some(value) => number(value)?,
                None => i32::MAX as f64,
            };
            let (min, max) = (min.max(0.0) as u64, max.max(0.0) as u64);
            if min >= max {
                return Err(EvalError("range"));
            }
            Val::Num(rand::thread_rng().gen_range(min..max) as f64)
        }
        Func::UnixTime => {
            let offset = match args.first() {
                Some(value) => number(value)?,
                None => 0.0,
            };
            Val::Num(chrono::Utc::now().timestamp() as f64 + offset)
        }
    };
    Ok(value)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}

/// Go's `url.QueryEscape`: unreserved bytes stay, a space becomes `+`, every
/// other byte `%XX`.
fn query_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Go's `url.QueryUnescape`: `+` is a space; a malformed escape is an error.
fn query_unescape(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = text.get(index + 1..index + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

// ---- Go regular expressions ----

/// Compiles a pattern with Go's meaning. Both engines are RE2-style, but Go's
/// `\d`, `\w`, `\s` and `\b` are ASCII while Rust's are Unicode: rewritten
/// as explicit ASCII classes, a version pattern like `([\w.]+)` stops at the
/// same character Nuclei's does.
pub fn go_regex(pattern: &str) -> Result<Regex, CompileError> {
    regex::RegexBuilder::new(&go_pattern(pattern))
        .size_limit(2 * 1024 * 1024)
        .build()
        .map_err(|_| CompileError::new("regex:invalid"))
}

/// Why a pattern does not compile, for the census.
#[cfg(test)]
pub fn regex_error(pattern: &str) -> Option<String> {
    regex::RegexBuilder::new(&go_pattern(pattern))
        .size_limit(2 * 1024 * 1024)
        .build()
        .err()
        .map(|error| format!("{error}\n  as Rust: {}", go_pattern(pattern)))
}

fn go_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    // Just after `[` or `[^`, where `]` is a literal.
    let mut class_start = false;
    // Where the open class began, and whether it holds \S or \D. Such a class
    // already holds every case variant of what else it lists, so folding
    // cannot change it; the regex crate still folds it code point by code
    // point, about 10 ms a pattern, so it is kept out of (?i).
    let mut class_open = 0;
    let mut class_caseless = false;
    while let Some(c) = chars.next() {
        if c == '\\' {
            let Some(next) = chars.next() else {
                out.push('\\');
                break;
            };
            if in_class && matches!(next, 'S' | 'D') {
                class_caseless = true;
            }
            let replacement = match (next, in_class) {
                ('d', false) => Some("[0-9]"),
                ('D', false) => Some("[^0-9]"),
                ('w', false) => Some("[0-9A-Za-z_]"),
                ('W', false) => Some("[^0-9A-Za-z_]"),
                ('s', false) => Some(r"[\t\n\f\r ]"),
                ('S', false) => Some(r"[^\t\n\f\r ]"),
                ('b', false) => Some(r"(?-u:\b)"),
                ('B', false) => Some(r"(?-u:\B)"),
                ('d', true) => Some("0-9"),
                ('w', true) => Some("0-9A-Za-z_"),
                ('s', true) => Some(r"\t\n\f\r "),
                ('D', true) => Some("[^0-9]"),
                ('W', true) => Some("[^0-9A-Za-z_]"),
                ('S', true) => Some(r"[^\t\n\f\r ]"),
                _ => None,
            };
            match replacement {
                Some(replacement) => out.push_str(replacement),
                None => {
                    out.push('\\');
                    out.push(next);
                }
            }
            class_start = false;
            continue;
        }
        if !in_class {
            // Go reads a `{` that does not start `{n}`, `{n,}` or `{n,m}` as a
            // plain character (`{,60}`, `{if`); Rust refuses the pattern.
            if c == '{' && !starts_repetition(chars.clone()) {
                out.push_str(r"\{");
                continue;
            }
            out.push(c);
            if c == '[' {
                in_class = true;
                class_start = true;
                class_open = out.len() - 1;
                class_caseless = false;
                if chars.peek() == Some(&'^') {
                    out.push('^');
                    chars.next();
                }
            }
            continue;
        }
        match c {
            ']' if !class_start => {
                in_class = false;
                out.push(']');
                if class_caseless {
                    out.insert_str(class_open, "(?-i:");
                    out.push(')');
                }
            }
            // A POSIX class such as [:alpha:] means the same in both.
            '[' if chars.peek() == Some(&':') => {
                out.push('[');
                for next in chars.by_ref() {
                    out.push(next);
                    if next == ']' {
                        break;
                    }
                }
            }
            // Rust reads `[` as a nested class and `&&`, `--`, `~~` as set
            // operations; in Go they are plain characters.
            '[' | '&' | '~' => {
                out.push('\\');
                out.push(c);
            }
            '-' if chars.peek() == Some(&'-') => {
                out.push_str(r"-\-");
                chars.next();
            }
            _ => out.push(c),
        }
        class_start = false;
    }
    out
}

/// Whether the text after a `{` is a Go repetition: digits, then `}`, `,}`
/// or `,` digits `}`.
fn starts_repetition(mut rest: std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    let mut digits = 0;
    while rest.peek().is_some_and(char::is_ascii_digit) {
        rest.next();
        digits += 1;
    }
    if digits == 0 {
        return false;
    }
    match rest.next() {
        Some('}') => true,
        Some(',') => {
            while rest.peek().is_some_and(char::is_ascii_digit) {
                rest.next();
            }
            rest.next() == Some('}')
        }
        _ => false,
    }
}

// ---- Interpolated text ----

/// Text with `{{…}}` markers, filled at run time.
#[derive(Clone, Debug)]
pub struct Interp {
    pieces: Vec<Piece>,
    allow: Allow,
}

#[derive(Clone, Debug)]
enum Piece {
    Text(String),
    Var(String),
    Expr(Expr),
    /// A marker with markers inside: filled from the inside out, then read.
    Nested(String),
}

/// A marker holding only a name is a variable. Names may contain hyphens
/// (`interactsh-url`), which an expression could not.
fn is_variable_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

impl Interp {
    pub fn compile(text: &str, allow: Allow) -> Result<Self, CompileError> {
        let mut pieces = Vec::new();
        let mut copied = 0;
        let push_text = |pieces: &mut Vec<Piece>, text: &str| match pieces.last_mut() {
            Some(Piece::Text(last)) => last.push_str(text),
            _ => pieces.push(Piece::Text(text.to_string())),
        };
        for (start, end) in marker_spans(text) {
            if start > copied {
                push_text(&mut pieces, &text[copied..start]);
            }
            let inner = text[start + 2..end - 2].trim();
            if inner.contains("{{") {
                Interp::compile(inner, allow)?;
                // Each inner marker fills in a value; any one stands in for
                // it, where leaving it out would read `md5({{n}})` as `md5()`.
                Expr::compile(&replace_markers(inner, "0"), allow)?;
                pieces.push(Piece::Nested(inner.to_string()));
            } else if is_variable_name(inner) {
                pieces.push(Piece::Var(inner.to_string()));
            } else if names_nothing(inner) {
                // Nuclei sends a marker such as `{{7*7}}` as written: it
                // probes for template injection, and sending the answer
                // instead would match any page that echoes it.
                push_text(&mut pieces, &text[start..end]);
            } else {
                pieces.push(Piece::Expr(Expr::compile(inner, allow)?));
            }
            copied = end;
        }
        if copied < text.len() {
            push_text(&mut pieces, &text[copied..]);
        }
        Ok(Self { pieces, allow })
    }

    /// The text when it has no markers.
    pub fn literal(&self) -> Option<&str> {
        match self.pieces.as_slice() {
            [] => Some(""),
            [Piece::Text(text)] => Some(text),
            _ => None,
        }
    }

    /// The names of plain-variable markers, for checking that each resolves.
    pub fn variables(&self) -> impl Iterator<Item = &str> {
        self.pieces.iter().filter_map(|piece| match piece {
            Piece::Var(name) => Some(name.as_str()),
            _ => None,
        })
    }

    pub fn render(&self, vars: &dyn Vars) -> Result<String, EvalError> {
        let mut out = String::new();
        for piece in &self.pieces {
            match piece {
                Piece::Text(text) => out.push_str(text),
                Piece::Var(name) => {
                    out.push_str(&vars.get(name).ok_or(EvalError("unresolved"))?.text())
                }
                Piece::Expr(expr) => out.push_str(&expr.eval(vars)?.text()),
                Piece::Nested(inner) => {
                    let filled = Interp::compile(inner, self.allow)
                        .map_err(|_| EvalError("nested"))?
                        .render(vars)?;
                    let expr =
                        Expr::compile(&filled, self.allow).map_err(|_| EvalError("nested"))?;
                    out.push_str(&expr.eval(vars)?.text());
                }
            }
            if out.len() > MAX_TEXT {
                return Err(EvalError("too_large"));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_operators_strings_and_calls() {
        let tokens =
            tokenize(r#"status_code==200 && !contains(tolower(body), '<html') || x !~ "a\"b""#)
                .unwrap();
        assert_eq!(tokens[0], Token::Ident("status_code".into()));
        assert_eq!(tokens[1], Token::Op("=="));
        assert_eq!(tokens[2], Token::Number("200".into()));
        assert_eq!(tokens[3], Token::Op("&&"));
        assert_eq!(tokens[4], Token::Op("!"));
        assert!(tokens.contains(&Token::Str("<html".into())));
        assert!(tokens.contains(&Token::Op("!~")));
        assert_eq!(tokens.last(), Some(&Token::Str("a\"b".into())));
        let (functions, variables) = names(&tokens);
        assert_eq!(functions, ["contains", "tolower"]);
        assert_eq!(variables, ["status_code", "body", "x"]);
    }

    #[test]
    fn rejects_what_it_cannot_read() {
        assert_eq!(tokenize("'open").unwrap_err().reason, "unterminated_string");
        assert_eq!(
            tokenize("a @ b").unwrap_err().reason,
            "unexpected_character"
        );
    }

    #[test]
    fn finds_outer_markers_and_ignores_unterminated_ones() {
        assert_eq!(
            markers("{{BaseURL}}/a?x={{ url_encode(\"{{command}}\") }}&z={{open"),
            ["BaseURL", "url_encode(\"{{command}}\")"]
        );
        assert_eq!(
            without_markers("url_encode(\"{{command}}\")"),
            "url_encode(\"\")"
        );
        assert_eq!(without_markers("a{{b}}c{{d}}e"), "ace");
    }
    struct Map(Vec<(&'static str, Val<'static>)>);

    impl Vars for Map {
        fn get(&self, name: &str) -> Option<Val<'_>> {
            self.0
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        }
    }

    fn vars() -> Map {
        Map(vec![
            ("status_code", Val::Num(200.0)),
            (
                "body",
                Val::Str(Cow::Borrowed("<html>Hello World 2.4.49</html>")),
            ),
            ("server", Val::Str(Cow::Borrowed("Apache/2.4.49"))),
            ("version", Val::Str(Cow::Borrowed("2.4.49"))),
            ("command", Val::Str(Cow::Borrowed("a b&c"))),
        ])
    }

    fn eval_text(source: &str) -> Result<String, EvalError> {
        let expr = Expr::compile(source, Allow::default()).unwrap();
        let vars = vars();
        let value = expr.eval(&vars)?;
        Ok(value.text().into_owned())
    }

    #[test]
    fn evaluates_like_govaluate() {
        assert_eq!(
            eval_text("status_code == 200 && contains(body, 'Hello')").unwrap(),
            "true"
        );
        assert_eq!(
            eval_text("!contains(tolower(body), '<html')").unwrap(),
            "false"
        );
        assert_eq!(eval_text("status_code == '200'").unwrap(), "false");
        assert_eq!(eval_text("status_code != '200'").unwrap(), "true");
        assert_eq!(eval_text("'a' + 1 + 2").unwrap(), "a12");
        assert_eq!(eval_text("1 + 2 * 3 ** 2").unwrap(), "19");
        assert_eq!(
            eval_text("len(body) > 10 ? 'long' : 'short'").unwrap(),
            "long"
        );
        assert_eq!(
            eval_text("server =~ 'Apache/2\\.4\\.4[0-9]'").unwrap(),
            "true"
        );
        assert_eq!(eval_text("server !~ '(?i)nginx'").unwrap(), "true");
        assert_eq!(
            eval_text("compare_versions(version, '>= 2.4.0', '< 2.4.50')").unwrap(),
            "true"
        );
        // A missing variable or a type mismatch fails the expression.
        assert_eq!(
            eval_text("contains(missing, 'x')"),
            Err(EvalError("unknown_variable"))
        );
        assert_eq!(eval_text("status_code > 'x'"), Err(EvalError("type")));
        assert_eq!(eval_text("!status_code"), Err(EvalError("type")));
    }

    #[test]
    fn helpers_match_nucleis_documented_examples() {
        for (source, expected) in [
            ("base64('Hello')", "SGVsbG8="),
            ("base64_decode('SGVsbG8=')", "Hello"),
            ("concat('Hello', 123, 'world')", "Hello123world"),
            ("contains_all('Hello everyone', 'lo', 'every')", "true"),
            ("contains_any('Hello everyone', 'abc', 'llo')", "true"),
            ("ends_with('Hello', 'lo')", "true"),
            ("equals_any(status_code, 200, 201)", "true"),
            ("hex_decode('6161')", "aa"),
            ("hex_encode('aa')", "6161"),
            ("join('_', 123, 'hello', 'world')", "123_hello_world"),
            ("len('Hello')", "5"),
            ("line_ends_with('Hello\nHi', 'lo')", "true"),
            ("line_starts_with('Hi\nHello', 'He')", "true"),
            ("md5('Hello')", "8b1a9953c4611296a827abf8c47804d7"),
            ("regex('H([a-z]+)o', 'Hello')", "true"),
            ("regex_all('H([a-z]+)o', 'Hallo', 'Hello')", "true"),
            ("regex_any('H([a-z]+)o', 'World', 'Hello')", "true"),
            ("replace('Hello', 'He', 'Ha')", "Hallo"),
            ("replace_regex('He123llo', '(\\\\d+)', '')", "Hello"),
            ("reverse('abc')", "cba"),
            ("sha1('Hello')", "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0"),
            (
                "sha256('Hello')",
                "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
            ),
            ("starts_with('Hello', 'He')", "true"),
            ("to_lower('HELLO')", "hello"),
            ("to_upper('hello')", "HELLO"),
            ("trim('aaaHelloddd', 'ad')", "Hello"),
            ("trim_left('aaaHelloddd', 'ad')", "Helloddd"),
            ("trim_prefix('aaHelloaa', 'aa')", "Helloaa"),
            ("trim_right('aaaHelloddd', 'ad')", "aaaHello"),
            ("trim_space('  Hello  ')", "Hello"),
            ("trim_suffix('aaHelloaa', 'aa')", "aaHello"),
            (
                "url_decode('https:%2F%2Fprojectdiscovery.io%3Ftest=1')",
                "https://projectdiscovery.io?test=1",
            ),
            (
                "url_encode('https://projectdiscovery.io/test?a=1')",
                "https%3A%2F%2Fprojectdiscovery.io%2Ftest%3Fa%3D1",
            ),
            ("to_number('12') + 1", "13"),
            ("to_string(200)", "200"),
        ] {
            assert_eq!(eval_text(source).unwrap(), expected, "{source}");
        }
    }

    #[test]
    fn helpers_templates_use_beyond_the_documented_examples() {
        for (source, expected) in [
            ("base64_py('hello')", "aGVsbG8=\n"),
            ("mmh3('hello')", "613153351"),
            ("mmh3('example')", "-266500539"),
            ("repeat('ab', 3)", "ababab"),
            ("substr('Hello', 1)", "ello"),
            ("substr('Hello', 1, 3)", "el"),
            ("padding('abc', 'xy', 6, 'prefix')", "xyxabc"),
            ("padding('abc', 'x', 5, 'suffix')", "abcxx"),
            ("padding('abcdef', 'x', 3, 'suffix')", "abcdef"),
            (
                "generate_jwt('{\"sub\":\"1\",\"admin\":true}', 'HS256', 'secret')",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwic3ViIjoiMSJ9.28jsumXSIeJju7qPBrqP6YZoKMf_eee2VaCHfNbvmhE",
            ),
            // Nuclei registers every helper without its underscores too.
            ("trimprefix('aaHello', 'aa')", "Hello"),
            ("startswith('Hello', 'He')", "true"),
        ] {
            assert_eq!(eval_text(source).unwrap(), expected, "{source}");
        }
        // Python's base64: a line break every 76 characters and at the end.
        assert_eq!(
            eval_text(&format!("base64_py('{}')", "x".repeat(60))).unwrap(),
            "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4\neHh4\n"
        );
        assert!(eval_text("substr('Hello', 4, 2)").is_err());
        assert!(eval_text("padding('a', 'x', 3, 'middle')").is_err());
        assert!(eval_text("generate_jwt('{}', 'RS256')").is_err());
    }

    /// A response whose body is bytes, not text.
    struct Raw(Vec<u8>);

    impl Vars for Raw {
        fn get(&self, name: &str) -> Option<Val<'_>> {
            (name == "body").then(|| Val::Str(String::from_utf8_lossy(&self.0)))
        }

        fn bytes(&self, name: &str) -> Option<Cow<'_, [u8]>> {
            (name == "body").then(|| Cow::Borrowed(self.0.as_slice()))
        }
    }

    #[test]
    fn hashes_and_encodings_of_the_body_read_its_bytes() {
        // A favicon is binary: as text it would lose bytes, and its hash with
        // them.
        let raw = Raw(vec![0x00, 0xff, 0x10, 0x89, 0x50]);
        let eval = |source: &str| {
            Expr::compile(source, Allow::default())
                .unwrap()
                .eval(&raw)
                .unwrap()
                .text()
                .into_owned()
        };
        assert_eq!(eval("mmh3(base64_py(body))"), "-96116520");
        assert_eq!(eval("md5(body)"), "68c74b24d9ac904125812084458b6935");
        assert_eq!(eval("len(body)"), "5");
    }

    #[test]
    fn date_time_fills_nucleis_percent_fields() {
        let at = chrono::NaiveDate::from_ymd_opt(2026, 3, 7)
            .unwrap()
            .and_hms_opt(4, 5, 9)
            .unwrap();
        assert_eq!(
            format_date_time("%Y-%M-%DT%H:%m:%sZ", at).unwrap(),
            "2026-03-07T04:05:09Z"
        );
        assert_eq!(format_date_time("%Y/%M", at).unwrap(), "2026/03");
        // A Go layout is not something Sniper formats.
        assert!(format_date_time("2006-01-02", at).is_err());
        assert!(Expr::compile("date_time('%Y')", Allow { random: true }).is_ok());
    }

    #[test]
    fn refuses_what_it_cannot_run() {
        let error = |source: &str| Expr::compile(source, Allow::default()).unwrap_err().0;
        assert_eq!(
            error("generate_java_gadget('dns', 'x')"),
            "fn:generate_java_gadget"
        );
        assert_eq!(error("rand_base(5)"), "randomness");
        assert_eq!(error("contains(body)"), "dsl:arity:contains");
        assert_eq!(error("regex(pattern, body)"), "dsl:regex_computed");
        assert_eq!(error("body =~ pattern"), "dsl:regex_computed");
        assert_eq!(error("status_code in [200]"), "dsl:operator:in");
        assert_eq!(error("a & b"), "dsl:operator:&");
        assert_eq!(error("(a"), "dsl:syntax");
        assert!(Expr::compile("rand_base(5)", Allow { random: true }).is_ok());
    }

    #[test]
    fn go_classes_stay_ascii() {
        let version = go_regex(r"Version ([\w.]+)").unwrap();
        let captured = version.captures("Version 2.4éx").unwrap();
        assert_eq!(&captured[1], "2.4");
        assert!(!go_regex(r"^\d+$").unwrap().is_match("١٢"));
        assert!(go_regex(r"\bword\b").unwrap().is_match("a word."));
        assert!(go_regex(r"[[]x").unwrap().is_match("[x"));
        assert!(go_regex(r"[a&&b]").unwrap().is_match("&"));
        assert!(go_regex(r"[[:alpha:]]+").unwrap().is_match("abc"));
        assert!(go_regex(r"[]a]").unwrap().is_match("]"));
        assert!(go_regex(r"(?i)X-Owa-Version[\s:]+")
            .unwrap()
            .is_match("x-owa-version: 1"));
        assert_eq!(go_regex(r"\Qa.b\E").unwrap_err().0, "regex:invalid");
        // Not repetitions in Go: plain braces.
        let literal = go_regex(r"[a-z]{,60}.cloudfront.net").unwrap();
        assert!(literal.is_match("x{,60}.cloudfront.net"));
        assert!(!literal.is_match("abc.cloudfront.net"));
        assert!(go_regex(r"function\(e\) *{if")
            .unwrap()
            .is_match("function(e) {if"));
        assert!(go_regex(r"a{2}b{1,}c{1,3}").unwrap().is_match("aabbc"));
    }

    #[test]
    fn classes_holding_s_or_d_are_not_case_folded() {
        // Folding cannot change such a class, but the regex crate folds it
        // code point by code point: 13 s for one template's 689 patterns.
        assert_eq!(
            go_pattern(r"(?i)a[^\S\r\n]*b"),
            r"(?i)a(?-i:[^[^\t\n\f\r ]\r\n])*b"
        );
        assert_eq!(go_pattern(r"(?i)[\Da]"), r"(?i)(?-i:[[^0-9]a])");
        let spaced = go_regex(r"(?i)key[^\S\r\n]*=").unwrap();
        assert!(spaced.is_match("KEY \t="));
        assert!(!spaced.is_match("KEY\n="));
        let not_digit = go_regex(r"(?i)^[\Dk]$").unwrap();
        assert!(not_digit.is_match("K") && not_digit.is_match("\u{212A}"));
        assert!(!not_digit.is_match("7"));
    }

    #[test]
    fn interpolates_markers_inside_out() {
        let vars = vars();
        let text = Interp::compile(
            "{{BaseURL}}/?q={{url_encode(\"{{command}}\")}}&v={{to_upper(version)}}",
            Allow::default(),
        )
        .unwrap();
        let base = Map(vec![
            ("BaseURL", Val::Str(Cow::Borrowed("https://example.com"))),
            ("command", Val::Str(Cow::Borrowed("a b&c"))),
            ("version", Val::Str(Cow::Borrowed("v1"))),
        ]);
        assert_eq!(
            text.render(&base).unwrap(),
            "https://example.com/?q=a+b%26c&v=V1"
        );
        let plain = Interp::compile("no markers", Allow::default()).unwrap();
        assert_eq!(plain.literal(), Some("no markers"));
        let missing = Interp::compile("{{nothing}}", Allow::default()).unwrap();
        assert_eq!(missing.render(&vars), Err(EvalError("unresolved")));
    }

    #[test]
    fn a_marker_inside_a_call_counts_as_an_argument() {
        let text = Interp::compile("{{md5({{num}})}}", Allow::default()).unwrap();
        let base = Map(vec![("num", Val::Str(Cow::Borrowed("999")))]);
        assert_eq!(
            text.render(&base).unwrap(),
            "b706835de79a2b4e80506f582af3676a"
        );
    }

    #[test]
    fn a_marker_that_names_nothing_is_sent_as_written() {
        // Nuclei leaves these alone: they probe for template injection, and
        // sending the answer instead would match any page that echoes it.
        let probe = "?q={{7*7}}&r={{228*'98'}}&s={{ \"a\" }}";
        let text = Interp::compile(probe, Allow::default()).unwrap();
        assert_eq!(text.literal(), Some(probe));
        assert_eq!(text.render(&vars()).unwrap(), probe);
    }
}
