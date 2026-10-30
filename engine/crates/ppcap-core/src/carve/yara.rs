//! A pure-Rust **YARA subset**, matched over carved files as they stream through the carver.
//!
//! Full YARA (yara-x) compiles rules with wasmtime, which needs a C compiler at build time and does
//! not run on the wasm target, so PacketPilot ships the part of the language most hunting rules use
//! and reports every rule it cannot evaluate as skipped (with the reason), like the Suricata subset
//! in `detect::rules`. Supported:
//!
//! - `rule name : tags { meta: … strings: … condition: … }`, `private` rules, references to earlier
//!   rules in a condition, comments.
//! - Text strings with `nocase`, `ascii`, `wide`; hex strings with `??` / nibble wildcards and
//!   bounded jumps `[n]`, `[n-m]`.
//! - Conditions: `and` `or` `not`, parentheses, `true` `false`, `$a`, `#a`, `$a at N`,
//!   `$a in (N..M)`, `filesize`, `KB`/`MB` sizes, `uint8/16/32` and their `be` forms,
//!   `any|all|N of them`, `… of ($a, $b*)`, comparisons and `+ - * \ %` on integers.
//!
//! Not supported (the rule is skipped): regular expressions, modules (`pe.`, `math.`, …), `for`
//! loops, `@a[i]` / `!a[i]`, `fullword`, `xor`, `base64`, hex alternatives, unbounded jumps,
//! `global` rules, `include`.
//!
//! Matching is streaming and bounded like the rest of the carver: a rolling window of the longest
//! pattern, the first [`PREFIX`] bytes for `uint` reads, and at most [`MAX_OFFSETS`] match offsets
//! per string. Nothing else of the file is kept.

use std::collections::HashMap;
use std::sync::Arc;

/// Bytes kept from the start of each file for `uintXX(offset)` reads.
const PREFIX: usize = 16 * 1024;
/// Match offsets remembered per string (for `at` / `in`); counts (`#a`) stay exact.
const MAX_OFFSETS: usize = 1024;
/// Longest jump accepted in a hex string.
const MAX_JUMP: usize = 1024;
/// Most rules one rule set holds.
const MAX_RULES: usize = 10_000;

/// A rule the parser could not take, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedYaraRule {
    /// The rule name, or `""` when the failure came before it.
    pub name: String,
    pub reason: String,
}

/// The result of parsing a rules file.
#[derive(Debug, Clone, Default)]
pub struct YaraParse {
    pub rules: YaraRules,
    pub skipped: Vec<SkippedYaraRule>,
}

/// A compiled rule set.
#[derive(Debug, Clone, Default)]
pub struct YaraRules {
    rules: Vec<Rule>,
    /// Every pattern of every rule, flattened, with its owner `(rule, string)`.
    patterns: Vec<(usize, usize, Pattern)>,
    /// Patterns whose first byte can be each value (the scan's candidate filter).
    starters: Vec<Vec<usize>>,
    /// Longest pattern in bytes (the rolling window).
    max_len: usize,
}

/// One rule that matched a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraHit {
    pub rule: String,
    pub tags: Vec<String>,
    /// `meta:` entries, in rule order (strings rendered as written, numbers and booleans as text).
    pub meta: Vec<(String, String)>,
}

impl YaraHit {
    /// The first of the named `meta` values present.
    pub fn meta_value(&self, names: &[&str]) -> Option<&str> {
        names.iter().find_map(|n| {
            self.meta
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.as_str())
        })
    }
}

#[derive(Debug, Clone)]
struct Rule {
    name: String,
    tags: Vec<String>,
    meta: Vec<(String, String)>,
    private: bool,
    cond: Expr,
    /// Per string, the constant `at` / `in` windows its condition asks about. Matches in them are
    /// remembered even past [`MAX_OFFSETS`], so a late `$a at 5000` is still answered.
    windows: Vec<Vec<(i64, i64)>>,
}

/// The constant value of an offset expression (`100`, `0x40 + 2`, `4KB`), if it has one.
fn const_int(e: &Expr) -> Option<i64> {
    match e {
        Expr::Int(i) => Some(*i),
        Expr::Arith(op, a, b) => {
            let (x, y) = (const_int(a)?, const_int(b)?);
            match op {
                '+' => Some(x.wrapping_add(y)),
                '-' => Some(x.wrapping_sub(y)),
                '*' => Some(x.wrapping_mul(y)),
                '\\' if y != 0 => Some(x / y),
                '%' if y != 0 => Some(x % y),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Collect the constant positional windows of `e` into `out[string]`.
fn collect_windows(e: &Expr, out: &mut [Vec<(i64, i64)>]) {
    match e {
        Expr::At(s, o) => {
            if let Some(v) = const_int(o) {
                out[*s].push((v, v));
            }
            collect_windows(o, out);
        }
        Expr::In(s, lo, hi) => {
            if let (Some(a), Some(b)) = (const_int(lo), const_int(hi)) {
                out[*s].push((a, b));
            }
            collect_windows(lo, out);
            collect_windows(hi, out);
        }
        Expr::Read(_, _, a) | Expr::Not(a) => collect_windows(a, out),
        Expr::And(a, b) | Expr::Or(a, b) | Expr::Cmp(_, a, b) | Expr::Arith(_, a, b) => {
            collect_windows(a, out);
            collect_windows(b, out);
        }
        Expr::Of(Quant::N(n), _) => collect_windows(n, out),
        _ => {}
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Pattern {
    Lit { bytes: Vec<u8>, nocase: bool },
    Hex(Vec<HexTok>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum HexTok {
    Byte { value: u8, mask: u8 },
    Jump { min: usize, max: usize },
}

impl Pattern {
    fn max_len(&self) -> usize {
        match self {
            Pattern::Lit { bytes, .. } => bytes.len(),
            Pattern::Hex(toks) => toks
                .iter()
                .map(|t| match t {
                    HexTok::Byte { .. } => 1,
                    HexTok::Jump { max, .. } => *max,
                })
                .sum(),
        }
    }

    /// Whether `b` can be this pattern's first byte.
    fn starts_with(&self, b: u8) -> bool {
        match self {
            Pattern::Lit { bytes, nocase } => match bytes.first() {
                Some(&f) if *nocase => f.eq_ignore_ascii_case(&b),
                Some(&f) => f == b,
                None => false,
            },
            Pattern::Hex(toks) => match toks.first() {
                Some(HexTok::Byte { value, mask }) => b & mask == *value,
                _ => true,
            },
        }
    }

    /// Whether the pattern matches at the start of `buf`. `complete` says `buf` holds every byte
    /// the file has left; otherwise a match needing more bytes than `buf` has is undecided (`None`).
    fn matches(&self, buf: &[u8], complete: bool) -> Option<bool> {
        match self {
            Pattern::Lit { bytes, nocase } => {
                if buf.len() < bytes.len() {
                    return if complete { Some(false) } else { None };
                }
                let w = &buf[..bytes.len()];
                Some(if *nocase {
                    w.eq_ignore_ascii_case(bytes)
                } else {
                    w == bytes.as_slice()
                })
            }
            Pattern::Hex(toks) => {
                // No match is longer than the pattern's longest form, so look no further.
                let longest = self.max_len();
                let w = &buf[..buf.len().min(longest)];
                hex_match(toks, w, complete || buf.len() >= longest)
            }
        }
    }
}

/// Hex matcher over bounded jumps: the set of reachable positions in `buf` is carried token by
/// token, so the work is linear in the tokens times the window, however many jumps there are
/// (backtracking would multiply the jump widths).
fn hex_match(toks: &[HexTok], buf: &[u8], complete: bool) -> Option<bool> {
    let n = buf.len();
    let mut at = vec![false; n + 1];
    at[0] = true;
    // A path ran past the end of `buf` while more bytes may still come.
    let mut cut = false;
    let mut next = vec![false; n + 1];
    for tok in toks {
        next.iter_mut().for_each(|x| *x = false);
        let mut any = false;
        match *tok {
            HexTok::Byte { value, mask } => {
                for p in (0..=n).filter(|&p| at[p]) {
                    if p == n {
                        cut |= !complete;
                    } else if buf[p] & mask == value {
                        next[p + 1] = true;
                        any = true;
                    }
                }
            }
            HexTok::Jump { min, max } => {
                // Mark every `p + min ..= p + max` with a running count of open ranges.
                let mut delta = vec![0i32; n + 2];
                for p in (0..=n).filter(|&p| at[p]) {
                    if p + max > n {
                        cut |= !complete;
                    }
                    if p + min <= n {
                        delta[p + min] += 1;
                        delta[(p + max).min(n) + 1] -= 1;
                    }
                }
                let mut open = 0;
                for (q, d) in delta.iter().take(n + 1).enumerate() {
                    open += d;
                    if open > 0 {
                        next[q] = true;
                        any = true;
                    }
                }
            }
        }
        std::mem::swap(&mut at, &mut next);
        if !any {
            return if cut { None } else { Some(false) };
        }
    }
    Some(true)
}

// ── conditions ──────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Expr {
    Bool(bool),
    Int(i64),
    Filesize,
    /// `$a`: the string matched at least once.
    Matched(usize),
    /// `#a`.
    Count(usize),
    /// `$a at N`.
    At(usize, Box<Expr>),
    /// `$a in (N..M)`.
    In(usize, Box<Expr>, Box<Expr>),
    /// `uintXX(off)`: bytes, big-endian.
    Read(u8, bool, Box<Expr>),
    /// `any|all|N of (set)`.
    Of(Quant, Vec<usize>),
    /// An earlier rule's result.
    RuleRef(usize),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(CmpOp, Box<Expr>, Box<Expr>),
    Arith(char, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone)]
enum Quant {
    Any,
    All,
    N(Box<Expr>),
}

#[derive(Debug, Clone, Copy)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Val {
    Int(i64),
    Bool(bool),
    /// YARA's `undefined` (a read past what is known): every comparison with it is false.
    Undef,
}

impl Val {
    fn truthy(self) -> bool {
        match self {
            Val::Bool(b) => b,
            Val::Int(i) => i != 0,
            Val::Undef => false,
        }
    }
    fn int(self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(i),
            Val::Bool(b) => Some(i64::from(b)),
            Val::Undef => None,
        }
    }
}

/// Per-file match state for one string.
#[derive(Debug, Clone, Default)]
struct StrState {
    count: u64,
    /// The first [`MAX_OFFSETS`] match offsets, ascending.
    offsets: Vec<u64>,
    /// Whether a match fell in each of the rule's constant windows for this string.
    window_hit: Vec<bool>,
}

impl StrState {
    /// Whether some offset in `lo..=hi` matched: `None` when only offsets past the kept ones
    /// could answer it.
    fn any_in(&self, lo: i64, hi: i64, windows: &[(i64, i64)]) -> Option<bool> {
        if self
            .offsets
            .iter()
            .any(|&o| (o as i64) >= lo && (o as i64) <= hi)
        {
            return Some(true);
        }
        if let Some(w) = windows.iter().position(|&w| w == (lo, hi)) {
            return Some(self.window_hit[w]);
        }
        let truncated = self.count > self.offsets.len() as u64;
        match self.offsets.last() {
            Some(&last) if truncated && hi > last as i64 => None,
            _ => Some(false),
        }
    }
}

struct EvalCtx<'a> {
    strings: &'a [StrState],
    windows: &'a [Vec<(i64, i64)>],
    filesize: u64,
    prefix: &'a [u8],
    rule_results: &'a [bool],
}

impl Expr {
    fn eval(&self, cx: &EvalCtx<'_>) -> Val {
        match self {
            Expr::Bool(b) => Val::Bool(*b),
            Expr::Int(i) => Val::Int(*i),
            Expr::Filesize => Val::Int(cx.filesize as i64),
            Expr::Matched(s) => Val::Bool(cx.strings[*s].count > 0),
            Expr::Count(s) => Val::Int(cx.strings[*s].count as i64),
            Expr::At(s, off) => match off.eval(cx).int() {
                Some(o) => cx.strings[*s]
                    .any_in(o, o, &cx.windows[*s])
                    .map_or(Val::Undef, Val::Bool),
                None => Val::Undef,
            },
            Expr::In(s, lo, hi) => match (lo.eval(cx).int(), hi.eval(cx).int()) {
                (Some(lo), Some(hi)) => cx.strings[*s]
                    .any_in(lo, hi, &cx.windows[*s])
                    .map_or(Val::Undef, Val::Bool),
                _ => Val::Undef,
            },
            Expr::Read(size, be, off) => {
                let Some(o) = off.eval(cx).int() else {
                    return Val::Undef;
                };
                let (o, n) = (o as usize, usize::from(*size));
                if o.checked_add(n).is_none_or(|end| end > cx.prefix.len()) {
                    return Val::Undef;
                }
                let bytes = &cx.prefix[o..o + n];
                let mut v: u64 = 0;
                if *be {
                    for &b in bytes {
                        v = (v << 8) | u64::from(b);
                    }
                } else {
                    for &b in bytes.iter().rev() {
                        v = (v << 8) | u64::from(b);
                    }
                }
                Val::Int(v as i64)
            }
            Expr::Of(q, set) => {
                let hit = set.iter().filter(|s| cx.strings[**s].count > 0).count();
                Val::Bool(match q {
                    Quant::Any => hit >= 1,
                    Quant::All => hit == set.len(),
                    Quant::N(n) => match n.eval(cx).int() {
                        Some(n) => hit as i64 >= n,
                        None => return Val::Undef,
                    },
                })
            }
            Expr::RuleRef(r) => Val::Bool(cx.rule_results[*r]),
            Expr::Not(e) => match e.eval(cx) {
                Val::Undef => Val::Undef,
                v => Val::Bool(!v.truthy()),
            },
            Expr::And(a, b) => Val::Bool(a.eval(cx).truthy() && b.eval(cx).truthy()),
            Expr::Or(a, b) => Val::Bool(a.eval(cx).truthy() || b.eval(cx).truthy()),
            Expr::Cmp(op, a, b) => match (a.eval(cx).int(), b.eval(cx).int()) {
                (Some(x), Some(y)) => Val::Bool(match op {
                    CmpOp::Eq => x == y,
                    CmpOp::Ne => x != y,
                    CmpOp::Lt => x < y,
                    CmpOp::Le => x <= y,
                    CmpOp::Gt => x > y,
                    CmpOp::Ge => x >= y,
                }),
                _ => Val::Undef,
            },
            Expr::Arith(op, a, b) => match (a.eval(cx).int(), b.eval(cx).int()) {
                (Some(x), Some(y)) => match op {
                    '+' => Val::Int(x.wrapping_add(y)),
                    '-' => Val::Int(x.wrapping_sub(y)),
                    '*' => Val::Int(x.wrapping_mul(y)),
                    '\\' if y != 0 => Val::Int(x / y),
                    '%' if y != 0 => Val::Int(x % y),
                    _ => Val::Undef,
                },
                _ => Val::Undef,
            },
        }
    }
}

// ── scanning ────────────────────────────────────────────────────────────────────────────────────

impl YaraRules {
    /// Parse a rules file. Never fails as a whole: each rule that can't be evaluated is reported
    /// in [`YaraParse::skipped`].
    pub fn parse(text: &str) -> YaraParse {
        Parser::new(text).run()
    }

    /// Rules loaded (private ones included).
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Parse another rules file into this set (e.g. a second `--yara` file). Its rules may
    /// reference rules already loaded; a name already present keeps its first definition and the
    /// duplicate is reported as skipped, with every other rule the file couldn't take.
    pub fn add(&mut self, text: &str) -> Vec<SkippedYaraRule> {
        let mut p = Parser::new(text);
        p.out = std::mem::take(self);
        p.names = p
            .out
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r.name.clone(), Some(i)))
            .collect();
        let parsed = p.run();
        *self = parsed.rules;
        parsed.skipped
    }

    fn index(&mut self) {
        self.starters = vec![Vec::new(); 256];
        self.max_len = 0;
        for (i, (_, _, p)) in self.patterns.iter().enumerate() {
            self.max_len = self.max_len.max(p.max_len());
            for b in 0..=255u8 {
                if p.starts_with(b) {
                    self.starters[usize::from(b)].push(i);
                }
            }
        }
    }
}

/// Streams one file's bytes through every rule's strings.
pub struct YaraScanner {
    rules: Arc<YaraRules>,
    states: Vec<Vec<StrState>>,
    /// Bytes from `window_start` on that some pattern starting there might still need.
    window: Vec<u8>,
    window_start: u64,
    prefix: Vec<u8>,
    size: u64,
}

impl YaraScanner {
    /// A fresh scanner for one file.
    pub fn new(rules: Arc<YaraRules>) -> YaraScanner {
        let states = rules
            .rules
            .iter()
            .map(|r| {
                r.windows
                    .iter()
                    .map(|w| StrState {
                        window_hit: vec![false; w.len()],
                        ..StrState::default()
                    })
                    .collect()
            })
            .collect();
        YaraScanner {
            rules,
            states,
            window: Vec::new(),
            window_start: 0,
            prefix: Vec::new(),
            size: 0,
        }
    }

    /// Fold the next run of file bytes.
    pub fn feed(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.prefix.len() < PREFIX {
            let take = (PREFIX - self.prefix.len()).min(bytes.len());
            self.prefix.extend_from_slice(&bytes[..take]);
        }
        self.size += bytes.len() as u64;
        if self.rules.patterns.is_empty() {
            return;
        }
        self.window.extend_from_slice(bytes);
        self.scan(false);
    }

    /// Test every start position that has enough bytes after it (all of them when `complete`), then
    /// drop what no remaining start can need.
    fn scan(&mut self, complete: bool) {
        let max = self.rules.max_len.max(1);
        let limit = if complete {
            self.window.len()
        } else {
            self.window.len().saturating_sub(max - 1)
        };
        // Strings already counted at this offset: an `ascii wide` string's two forms can both
        // match at one offset, which is still one occurrence.
        let mut counted: Vec<(usize, usize)> = Vec::new();
        let mut i = 0;
        while i < limit {
            let b = self.window[i];
            counted.clear();
            for &pi in &self.rules.starters[usize::from(b)] {
                let (ri, si, ref p) = self.rules.patterns[pi];
                // Without `complete`, `limit` leaves `max` bytes after `i`, so this decides.
                if counted.contains(&(ri, si))
                    || p.matches(&self.window[i..], complete) != Some(true)
                {
                    continue;
                }
                counted.push((ri, si));
                let off = self.window_start + i as u64;
                let st = &mut self.states[ri][si];
                st.count += 1;
                if st.offsets.len() < MAX_OFFSETS {
                    st.offsets.push(off);
                }
                for (w, &(lo, hi)) in self.rules.rules[ri].windows[si].iter().enumerate() {
                    if (off as i64) >= lo && (off as i64) <= hi {
                        st.window_hit[w] = true;
                    }
                }
            }
            i += 1;
        }
        self.window.drain(..limit);
        self.window_start += limit as u64;
    }

    /// Evaluate every rule against the whole file; the non-private ones that hold.
    pub fn finish(mut self) -> Vec<YaraHit> {
        self.scan(true);
        let mut results = vec![false; self.rules.rules.len()];
        let mut hits = Vec::new();
        for (ri, rule) in self.rules.rules.iter().enumerate() {
            // Each rule's string ids index into its own states.
            let cx = EvalCtx {
                strings: &self.states[ri],
                windows: &rule.windows,
                filesize: self.size,
                prefix: &self.prefix,
                rule_results: &results,
            };
            let ok = rule.cond.eval(&cx).truthy();
            results[ri] = ok;
            if ok && !rule.private {
                hits.push(YaraHit {
                    rule: rule.name.clone(),
                    tags: rule.tags.clone(),
                    meta: rule.meta.clone(),
                });
            }
        }
        hits
    }
}

// ── lexer ───────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    /// `$a`, `#a`, `@a`, `!a` (the sigil is kept).
    Var(char, String),
    Int(i64),
    Str(Vec<u8>),
    Hex(String),
    Regex,
    Punct(&'static str),
}

fn lex(text: &str) -> Result<Vec<Tok>, String> {
    let b = text.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            match text[i + 2..].find("*/") {
                Some(e) => i += e + 4,
                None => return Err("unterminated comment".into()),
            }
        } else if c == b'"' {
            let (s, n) = lex_string(&b[i..])?;
            out.push(Tok::Str(s));
            i += n;
        } else if c == b'{' && matches!(out.last(), Some(Tok::Punct("="))) {
            match text[i + 1..].find('}') {
                Some(e) => {
                    out.push(Tok::Hex(text[i + 1..i + 1 + e].to_string()));
                    i += e + 2;
                }
                None => return Err("unterminated hex string".into()),
            }
        } else if c == b'/' && matches!(out.last(), Some(Tok::Punct("="))) {
            // A regular expression string: skip to its closing slash (escapes honored).
            i += 1;
            while i < b.len() && b[i] != b'/' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1;
            }
            out.push(Tok::Regex);
        } else if c == b'$'
            || (matches!(c, b'#' | b'@' | b'!')
                && b.get(i + 1)
                    .is_some_and(|n| n.is_ascii_alphanumeric() || *n == b'_' || *n == b'*'))
        {
            // A lone `$` is the anonymous string; `#`, `@` and `!` need a name to be sigils.
            let start = i + 1;
            let mut j = start;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'*') {
                j += 1;
            }
            out.push(Tok::Var(char::from(c), text[start..j].to_string()));
            i = j;
        } else if c.is_ascii_digit() {
            let start = i;
            let mut j = i;
            let v = if b[i..].starts_with(b"0x") || b[i..].starts_with(b"0X") {
                j += 2;
                while j < b.len() && b[j].is_ascii_hexdigit() {
                    j += 1;
                }
                i64::from_str_radix(&text[start + 2..j], 16).map_err(|e| e.to_string())?
            } else {
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                text[start..j].parse::<i64>().map_err(|e| e.to_string())?
            };
            let v = if b[j..].starts_with(b"KB") {
                j += 2;
                v.saturating_mul(1024)
            } else if b[j..].starts_with(b"MB") {
                j += 2;
                v.saturating_mul(1024 * 1024)
            } else {
                v
            };
            out.push(Tok::Int(v));
            i = j;
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'.') {
                i += 1;
            }
            out.push(Tok::Ident(text[start..i].to_string()));
        } else {
            const PUNCT: &[&str] = &[
                "..", "==", "!=", "<=", ">=", "<<", ">>", "(", ")", "[", "]", "{", "}", ",", ":",
                "=", "<", ">", "+", "-", "*", "\\", "%", "&", "|", "^", "~", ".",
            ];
            match PUNCT.iter().find(|p| b[i..].starts_with(p.as_bytes())) {
                Some(p) => {
                    out.push(Tok::Punct(p));
                    i += p.len();
                }
                None => return Err(format!("unexpected character {:?}", char::from(c))),
            }
        }
    }
    Ok(out)
}

/// A quoted string with YARA's escapes; returns the bytes and how much input it used.
fn lex_string(b: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut out = Vec::new();
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Ok((out, i + 1)),
            b'\\' => {
                let e = *b.get(i + 1).ok_or("unterminated string")?;
                i += 2;
                match e {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'x' => {
                        let h = b.get(i..i + 2).ok_or("bad \\x escape")?;
                        let h = std::str::from_utf8(h).map_err(|_| "bad \\x escape")?;
                        out.push(u8::from_str_radix(h, 16).map_err(|_| "bad \\x escape")?);
                        i += 2;
                    }
                    _ => return Err(format!("unknown escape \\{}", char::from(e))),
                }
            }
            b'\n' => return Err("newline in string".into()),
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Err("unterminated string".into())
}

// ── parser ──────────────────────────────────────────────────────────────────────────────────────

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    lex_error: Option<String>,
    out: YaraRules,
    skipped: Vec<SkippedYaraRule>,
    /// Names of every rule seen so far, to index references; `None` for a skipped one.
    names: HashMap<String, Option<usize>>,
}

/// One rule's string table while its condition parses.
struct StrTable {
    ids: Vec<String>,
}

impl StrTable {
    fn find(&self, id: &str) -> Result<usize, String> {
        self.ids
            .iter()
            .position(|s| s == id)
            .ok_or_else(|| format!("undefined string ${id}"))
    }

    /// Ids matching `$name` or the wildcard `$prefix*`.
    fn set(&self, pat: &str) -> Result<Vec<usize>, String> {
        let v: Vec<usize> = match pat.strip_suffix('*') {
            Some(prefix) => self
                .ids
                .iter()
                .enumerate()
                .filter(|(_, s)| s.starts_with(prefix))
                .map(|(i, _)| i)
                .collect(),
            None => vec![self.find(pat)?],
        };
        if v.is_empty() {
            return Err(format!("no string matches ${pat}"));
        }
        Ok(v)
    }
}

impl Parser {
    fn new(text: &str) -> Parser {
        let (toks, lex_error) = match lex(text) {
            Ok(t) => (t, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        Parser {
            toks,
            pos: 0,
            lex_error,
            out: YaraRules::default(),
            skipped: Vec::new(),
            names: HashMap::new(),
        }
    }

    fn run(mut self) -> YaraParse {
        if let Some(e) = self.lex_error.take() {
            self.skipped.push(SkippedYaraRule {
                name: String::new(),
                reason: format!("the file could not be read as YARA: {e}"),
            });
            return self.finish();
        }
        while self.pos < self.toks.len() {
            let start = self.pos;
            match self.peek_ident() {
                Some("import") => {
                    self.pos += 1;
                    if matches!(self.toks.get(self.pos), Some(Tok::Str(_))) {
                        self.pos += 1;
                    }
                }
                Some("include") => {
                    self.pos += 2;
                    self.skipped.push(SkippedYaraRule {
                        name: String::new(),
                        reason: "`include` is not supported; pass each file with --yara".into(),
                    });
                }
                Some("rule" | "private" | "global") => {
                    let name = self.rule_name();
                    match self.rule() {
                        Ok(()) => {}
                        Err(reason) => {
                            // A failed duplicate leaves the first definition referable.
                            if let Some(n) = &name {
                                self.names.entry(n.clone()).or_insert(None);
                            }
                            self.skipped.push(SkippedYaraRule {
                                name: name.unwrap_or_default(),
                                reason,
                            });
                            self.skip_rule(start);
                        }
                    }
                }
                _ => {
                    self.skipped.push(SkippedYaraRule {
                        name: String::new(),
                        reason: format!("unexpected {:?} outside a rule", self.toks[self.pos]),
                    });
                    self.pos += 1;
                }
            }
            if self.pos == start {
                self.pos += 1;
            }
        }
        self.finish()
    }

    fn finish(mut self) -> YaraParse {
        self.out.index();
        YaraParse {
            rules: self.out,
            skipped: self.skipped,
        }
    }

    /// The rule name that follows the modifiers at the current position, if any.
    fn rule_name(&self) -> Option<String> {
        let mut i = self.pos;
        while let Some(Tok::Ident(w)) = self.toks.get(i) {
            if w == "rule" {
                return match self.toks.get(i + 1) {
                    Some(Tok::Ident(n)) => Some(n.clone()),
                    _ => None,
                };
            }
            i += 1;
        }
        None
    }

    /// After a failed rule, move past its closing brace.
    fn skip_rule(&mut self, start: usize) {
        let mut i = start;
        let mut depth = 0i32;
        let mut opened = false;
        while i < self.toks.len() {
            match &self.toks[i] {
                Tok::Punct("{") => {
                    depth += 1;
                    opened = true;
                }
                Tok::Punct("}") => {
                    depth -= 1;
                    if opened && depth == 0 {
                        self.pos = i + 1;
                        return;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        self.pos = self.toks.len();
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn peek_ident(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Ident(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn eat_punct(&mut self, p: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Punct(q)) if *q == p) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect_punct(&mut self, p: &str) -> Result<(), String> {
        if self.eat_punct(p) {
            Ok(())
        } else {
            Err(format!("expected `{p}`, found {:?}", self.peek()))
        }
    }

    fn eat_ident(&mut self, w: &str) -> bool {
        if self.peek_ident() == Some(w) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn rule(&mut self) -> Result<(), String> {
        let mut private = false;
        loop {
            match self.peek_ident() {
                Some("private") => {
                    private = true;
                    self.pos += 1;
                }
                Some("global") => return Err("`global` rules are not supported".into()),
                Some("rule") => {
                    self.pos += 1;
                    break;
                }
                _ => return Err("expected `rule`".into()),
            }
        }
        let name = match self.next() {
            Some(Tok::Ident(n)) if !n.contains('.') => n,
            other => return Err(format!("bad rule name {other:?}")),
        };
        if self.names.contains_key(&name) {
            return Err("duplicate rule name (the first definition wins)".into());
        }
        let mut tags = Vec::new();
        if self.eat_punct(":") {
            while let Some(Tok::Ident(t)) = self.peek() {
                tags.push(t.clone());
                self.pos += 1;
            }
        }
        self.expect_punct("{")?;
        let mut meta = Vec::new();
        let mut table = StrTable { ids: Vec::new() };
        let mut pats: Vec<(usize, Pattern)> = Vec::new();
        let cond = loop {
            match self.next() {
                Some(Tok::Ident(s)) if s == "meta" => {
                    self.expect_punct(":")?;
                    while let (Some(Tok::Ident(k)), Some(Tok::Punct("="))) =
                        (self.peek().cloned(), self.toks.get(self.pos + 1))
                    {
                        self.pos += 2;
                        let v = match self.next() {
                            Some(Tok::Str(b)) => String::from_utf8_lossy(&b).into_owned(),
                            Some(Tok::Int(i)) => i.to_string(),
                            Some(Tok::Punct("-")) => match self.next() {
                                Some(Tok::Int(i)) => (-i).to_string(),
                                o => return Err(format!("bad meta value {o:?}")),
                            },
                            Some(Tok::Ident(b)) if b == "true" || b == "false" => b,
                            o => return Err(format!("bad meta value {o:?}")),
                        };
                        meta.push((k, v));
                    }
                }
                Some(Tok::Ident(s)) if s == "strings" => {
                    self.expect_punct(":")?;
                    while let Some(Tok::Var('$', id)) = self.peek().cloned() {
                        self.pos += 1;
                        self.expect_punct("=")?;
                        let id = if id.is_empty() {
                            format!("anonymous #{}", table.ids.len())
                        } else {
                            id
                        };
                        if table.ids.contains(&id) {
                            return Err(format!("duplicate string ${id}"));
                        }
                        let si = table.ids.len();
                        table.ids.push(id);
                        for p in self.string_def()? {
                            pats.push((si, p));
                        }
                    }
                }
                Some(Tok::Ident(s)) if s == "condition" => {
                    self.expect_punct(":")?;
                    let cond = self.expr(&table)?;
                    self.expect_punct("}")?;
                    break cond;
                }
                other => return Err(format!("unexpected {other:?} in rule body")),
            }
        };
        if self.out.rules.len() >= MAX_RULES {
            return Err(format!("more than {MAX_RULES} rules"));
        }
        let ri = self.out.rules.len();
        self.names.insert(name.clone(), Some(ri));
        for (si, p) in pats {
            self.out.patterns.push((ri, si, p));
        }
        let mut windows = vec![Vec::new(); table.ids.len()];
        collect_windows(&cond, &mut windows);
        self.out.rules.push(Rule {
            name,
            tags,
            meta,
            private,
            cond,
            windows,
        });
        Ok(())
    }

    /// One string's value and modifiers, as its match variants.
    fn string_def(&mut self) -> Result<Vec<Pattern>, String> {
        match self.next() {
            Some(Tok::Str(bytes)) => {
                if bytes.is_empty() {
                    return Err("empty text string".into());
                }
                let (mut nocase, mut ascii, mut wide) = (false, false, false);
                while let Some(m) = self.peek_ident().map(str::to_string) {
                    match m.as_str() {
                        "nocase" => nocase = true,
                        "ascii" => ascii = true,
                        "wide" => wide = true,
                        "private" => {}
                        "fullword" | "xor" | "base64" | "base64wide" => {
                            return Err(format!("string modifier `{m}` is not supported"))
                        }
                        _ => break,
                    }
                    self.pos += 1;
                    if m == "xor" || m.starts_with("base64") {
                        break;
                    }
                }
                let mut v = Vec::new();
                if ascii || !wide {
                    v.push(Pattern::Lit {
                        bytes: bytes.clone(),
                        nocase,
                    });
                }
                if wide {
                    v.push(Pattern::Lit {
                        bytes: bytes.iter().flat_map(|&c| [c, 0]).collect(),
                        nocase,
                    });
                }
                Ok(v)
            }
            Some(Tok::Hex(body)) => {
                while let Some(m) = self.peek_ident() {
                    match m {
                        "private" => self.pos += 1,
                        "nocase" | "ascii" | "wide" | "fullword" | "xor" | "base64"
                        | "base64wide" => {
                            return Err(format!("modifier `{m}` on a hex string is not supported"))
                        }
                        _ => break,
                    }
                }
                Ok(vec![Pattern::Hex(parse_hex(&body)?)])
            }
            Some(Tok::Regex) => Err("regular expressions are not supported".into()),
            other => Err(format!("bad string value {other:?}")),
        }
    }

    // expr := or
    fn expr(&mut self, t: &StrTable) -> Result<Expr, String> {
        let mut a = self.and(t)?;
        while self.eat_ident("or") {
            a = Expr::Or(Box::new(a), Box::new(self.and(t)?));
        }
        Ok(a)
    }

    fn and(&mut self, t: &StrTable) -> Result<Expr, String> {
        let mut a = self.not(t)?;
        while self.eat_ident("and") {
            a = Expr::And(Box::new(a), Box::new(self.not(t)?));
        }
        Ok(a)
    }

    fn not(&mut self, t: &StrTable) -> Result<Expr, String> {
        if self.eat_ident("not") {
            return Ok(Expr::Not(Box::new(self.not(t)?)));
        }
        self.cmp(t)
    }

    fn cmp(&mut self, t: &StrTable) -> Result<Expr, String> {
        let a = self.sum(t)?;
        let op = match self.peek() {
            Some(Tok::Punct("==")) => CmpOp::Eq,
            Some(Tok::Punct("!=")) => CmpOp::Ne,
            Some(Tok::Punct("<")) => CmpOp::Lt,
            Some(Tok::Punct("<=")) => CmpOp::Le,
            Some(Tok::Punct(">")) => CmpOp::Gt,
            Some(Tok::Punct(">=")) => CmpOp::Ge,
            Some(Tok::Ident(w)) if matches!(w.as_str(), "contains" | "matches" | "icontains") => {
                return Err(format!("`{w}` is not supported"))
            }
            _ => return Ok(a),
        };
        self.pos += 1;
        let b = self.sum(t)?;
        Ok(Expr::Cmp(op, Box::new(a), Box::new(b)))
    }

    fn sum(&mut self, t: &StrTable) -> Result<Expr, String> {
        let mut a = self.product(t)?;
        loop {
            let op = match self.peek() {
                Some(Tok::Punct("+")) => '+',
                Some(Tok::Punct("-")) => '-',
                _ => return Ok(a),
            };
            self.pos += 1;
            a = Expr::Arith(op, Box::new(a), Box::new(self.product(t)?));
        }
    }

    fn product(&mut self, t: &StrTable) -> Result<Expr, String> {
        let mut a = self.atom(t)?;
        loop {
            let op = match self.peek() {
                Some(Tok::Punct("*")) => '*',
                Some(Tok::Punct("\\")) => '\\',
                Some(Tok::Punct("%")) => '%',
                Some(Tok::Punct(p @ ("&" | "|" | "^" | "<<" | ">>"))) => {
                    return Err(format!("operator `{p}` is not supported"))
                }
                _ => return Ok(a),
            };
            self.pos += 1;
            a = Expr::Arith(op, Box::new(a), Box::new(self.atom(t)?));
        }
    }

    fn atom(&mut self, t: &StrTable) -> Result<Expr, String> {
        match self.next() {
            Some(Tok::Punct("(")) => {
                let e = self.expr(t)?;
                self.expect_punct(")")?;
                Ok(e)
            }
            Some(Tok::Punct("-")) => match self.next() {
                Some(Tok::Int(i)) => Ok(Expr::Int(-i)),
                o => Err(format!("unexpected {o:?} after `-`")),
            },
            Some(Tok::Int(i)) => {
                if self.peek_ident() == Some("of") {
                    self.pos += 1;
                    return self.of(t, Quant::N(Box::new(Expr::Int(i))));
                }
                Ok(Expr::Int(i))
            }
            Some(Tok::Var('$', id)) => {
                let s = t.find(&id)?;
                if self.eat_ident("at") {
                    return Ok(Expr::At(s, Box::new(self.sum(t)?)));
                }
                if self.eat_ident("in") {
                    self.expect_punct("(")?;
                    let lo = self.sum(t)?;
                    self.expect_punct("..")?;
                    let hi = self.sum(t)?;
                    self.expect_punct(")")?;
                    return Ok(Expr::In(s, Box::new(lo), Box::new(hi)));
                }
                Ok(Expr::Matched(s))
            }
            Some(Tok::Var('#', id)) => Ok(Expr::Count(t.find(&id)?)),
            Some(Tok::Var(c, _)) => Err(format!("`{c}` string references are not supported")),
            Some(Tok::Ident(w)) => match w.as_str() {
                "true" => Ok(Expr::Bool(true)),
                "false" => Ok(Expr::Bool(false)),
                "filesize" => Ok(Expr::Filesize),
                "any" => {
                    self.expect_of()?;
                    self.of(t, Quant::Any)
                }
                "all" => {
                    self.expect_of()?;
                    self.of(t, Quant::All)
                }
                "none" => {
                    self.expect_of()?;
                    let set = self.of_set(t)?;
                    Ok(Expr::Not(Box::new(Expr::Of(Quant::Any, set))))
                }
                "for" => Err("`for` loops are not supported".into()),
                "entrypoint" => Err("`entrypoint` is not supported".into()),
                w if w.starts_with("uint") || w.starts_with("int") => {
                    let (size, be) = match w {
                        "uint8" | "uint8be" => (1, false),
                        "uint16" => (2, false),
                        "uint32" => (4, false),
                        "uint16be" => (2, true),
                        "uint32be" => (4, true),
                        _ => return Err(format!("`{w}` is not supported")),
                    };
                    self.expect_punct("(")?;
                    let off = self.expr(t)?;
                    self.expect_punct(")")?;
                    Ok(Expr::Read(size, be, Box::new(off)))
                }
                w if w.contains('.') => Err(format!(
                    "module field `{w}` is not supported (modules such as pe and math are not \
                     available)"
                )),
                w => match self.names.get(w) {
                    Some(Some(r)) => Ok(Expr::RuleRef(*r)),
                    Some(None) => Err(format!("references rule `{w}`, which was skipped")),
                    None => Err(format!("unknown identifier `{w}`")),
                },
            },
            o => Err(format!("unexpected {o:?} in condition")),
        }
    }

    fn expect_of(&mut self) -> Result<(), String> {
        if self.eat_ident("of") {
            Ok(())
        } else {
            Err("expected `of`".into())
        }
    }

    fn of(&mut self, t: &StrTable, q: Quant) -> Result<Expr, String> {
        let set = self.of_set(t)?;
        Ok(Expr::Of(q, set))
    }

    fn of_set(&mut self, t: &StrTable) -> Result<Vec<usize>, String> {
        if self.eat_ident("them") {
            if t.ids.is_empty() {
                return Err("`of them` in a rule without strings".into());
            }
            return Ok((0..t.ids.len()).collect());
        }
        self.expect_punct("(")?;
        let mut set = Vec::new();
        loop {
            match self.next() {
                Some(Tok::Var('$', id)) => {
                    for s in t.set(&id)? {
                        if !set.contains(&s) {
                            set.push(s);
                        }
                    }
                }
                o => return Err(format!("unexpected {o:?} in a string set")),
            }
            if self.eat_punct(")") {
                return Ok(set);
            }
            self.expect_punct(",")?;
        }
    }
}

/// Parse the inside of a hex string (`4D 5A ?? [2-4] 9?`).
fn parse_hex(body: &str) -> Result<Vec<HexTok>, String> {
    let mut toks = Vec::new();
    let mut chars = body.chars().filter(|c| !c.is_whitespace()).peekable();
    let nib = |c: char| -> Result<(u8, u8), String> {
        if c == '?' {
            Ok((0, 0))
        } else {
            c.to_digit(16)
                .map(|d| (d as u8, 0xF))
                .ok_or_else(|| format!("bad hex digit {c:?}"))
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '[' => {
                let mut spec = String::new();
                for d in chars.by_ref() {
                    if d == ']' {
                        break;
                    }
                    spec.push(d);
                }
                let (min, max) = match spec.split_once('-') {
                    Some((a, b)) => {
                        if b.is_empty() {
                            return Err("unbounded jumps are not supported".into());
                        }
                        let a = if a.is_empty() {
                            0
                        } else {
                            a.parse().map_err(|_| "bad jump")?
                        };
                        (a, b.parse::<usize>().map_err(|_| "bad jump")?)
                    }
                    None => {
                        let n = spec.parse::<usize>().map_err(|_| "bad jump")?;
                        (n, n)
                    }
                };
                if min > max || max > MAX_JUMP {
                    return Err(format!("jump [{spec}] is not supported (max {MAX_JUMP})"));
                }
                toks.push(HexTok::Jump { min, max });
            }
            '(' | '|' | ')' => return Err("hex alternatives are not supported".into()),
            '~' => return Err("hex `~` negation is not supported".into()),
            hi => {
                let lo = chars.next().ok_or("odd number of hex digits")?;
                let (hv, hm) = nib(hi)?;
                let (lv, lm) = nib(lo)?;
                toks.push(HexTok::Byte {
                    value: (hv << 4) | lv,
                    mask: (hm << 4) | lm,
                });
            }
        }
    }
    if !matches!(toks.first(), Some(HexTok::Byte { .. }))
        || !matches!(toks.last(), Some(HexTok::Byte { .. }))
    {
        return Err("a hex string must start and end with a byte".into());
    }
    Ok(toks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(rules: &str, data: &[u8], chunk: usize) -> (Vec<String>, Vec<SkippedYaraRule>) {
        let p = YaraRules::parse(rules);
        let mut s = YaraScanner::new(Arc::new(p.rules));
        for c in data.chunks(chunk.max(1)) {
            s.feed(c);
        }
        (s.finish().into_iter().map(|h| h.rule).collect(), p.skipped)
    }

    const PE: &[u8] = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00";

    #[test]
    fn text_hex_and_counts_match_across_chunk_boundaries() {
        let rules = r#"
            rule two_hits : tool loader {
                meta:
                    description = "test"
                    severity = "high"
                strings:
                    $a = "evil" nocase
                    $b = { 4D 5A ?? 00 [1-3] 00 }
                condition:
                    #a == 2 and $b at 0 and filesize < 1KB
            }
            rule wide_only { strings: $w = "cmd" wide condition: $w }
        "#;
        let mut data = PE.to_vec();
        data.extend_from_slice(b"..EVIL..eViL..c\0m\0d\0");
        for chunk in [1, 3, 7, 1000] {
            let (hits, skipped) = scan(rules, &data, chunk);
            assert!(skipped.is_empty(), "{skipped:?}");
            assert_eq!(hits, vec!["two_hits", "wide_only"], "chunk {chunk}");
        }
    }

    #[test]
    fn uint_reads_quantifiers_and_rule_references() {
        let rules = r#"
            private rule is_pe { condition: uint16(0) == 0x5A4D and uint32be(0) == 0x4D5A9000 }
            rule packed {
                strings:
                    $u1 = "UPX0"
                    $u2 = "UPX1"
                    $x = "nope"
                condition:
                    is_pe and 2 of ($u*) and not $x and none of ($x)
            }
            rule any_them { strings: $a = "UPX1" $b = "zzz" condition: any of them }
            rule all_them { strings: $a = "UPX1" $b = "zzz" condition: all of them }
            rule in_range { strings: $a = "UPX1" condition: $a in (16..40) and #a + 1 == 2 }
        "#;
        let mut data = PE.to_vec();
        data.extend_from_slice(b"UPX0UPX1");
        let (hits, skipped) = scan(rules, &data, 5);
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(hits, vec!["packed", "any_them", "in_range"]);
    }

    #[test]
    fn unsupported_features_skip_only_their_rule() {
        let rules = r#"
            import "pe"
            rule uses_regex { strings: $r = /ab+c/ condition: $r }
            rule uses_module { condition: pe.number_of_sections > 2 }
            rule uses_for { strings: $a = "x" condition: for any i in (1..#a): (@a[i] < 10) }
            rule uses_fullword { strings: $a = "x" fullword condition: $a }
            rule refs_skipped { condition: uses_regex }
            rule fine { strings: $a = "abc" condition: $a }
        "#;
        let (hits, skipped) = scan(rules, b"xxabcxx", 4);
        assert_eq!(hits, vec!["fine"]);
        let names: Vec<&str> = skipped.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "uses_regex",
                "uses_module",
                "uses_for",
                "uses_fullword",
                "refs_skipped"
            ]
        );
        assert!(skipped[0].reason.contains("regular expressions"));
        assert!(skipped[1].reason.contains("module"));
    }

    #[test]
    fn reads_past_the_prefix_are_undefined_not_true() {
        let rules = "rule r { condition: uint8(100) == 0 or not (uint8(100) == 1) }";
        let (hits, _) = scan(rules, b"short", 2);
        // `not undefined` stays undefined (false), as in YARA.
        assert!(hits.is_empty());
    }

    fn hits(rules: YaraRules, data: &[u8]) -> Vec<String> {
        let mut s = YaraScanner::new(Arc::new(rules));
        s.feed(data);
        s.finish().into_iter().map(|h| h.rule).collect()
    }

    #[test]
    fn a_second_file_adds_rules_that_reference_the_first() {
        let mut a = YaraRules::parse(
            "private rule is_mz { condition: uint16(0) == 0x5A4D } rule one { strings: $a = \"aa\" condition: $a }",
        )
        .rules;
        let skipped = a.add(
            "rule one { condition: true } rule two { strings: $b = \"bb\" condition: $b and is_mz }",
        );
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert_eq!(skipped[0].name, "one");
        assert_eq!(a.len(), 3);
        // A later duplicate is skipped and references still reach the first definition.
        let skipped = a.add("rule is_mz { condition: false } rule three { condition: is_mz }");
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert_eq!(hits(a, b"MZbbzz"), vec!["two", "three"]);
    }

    #[test]
    fn late_offsets_past_the_kept_list_are_still_answered() {
        let data = vec![b'A'; 3000];
        let r = YaraRules::parse(
            r#"rule at_end { strings: $a = "A" condition: $a at 2999 and $a in (2500..2600) and #a == 3000 }
               rule dyn_at { strings: $a = "A" condition: $a at (filesize - 1) }
               rule early { strings: $a = "A" condition: $a at 10 }"#,
        );
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
        // A non-constant offset past the kept matches is undefined, not a guess.
        assert_eq!(hits(r.rules, &data), vec!["at_end", "early"]);
    }

    #[test]
    fn an_ascii_wide_string_counts_one_occurrence_per_offset() {
        let r = YaraRules::parse(r#"rule one { strings: $a = "A" ascii wide condition: #a == 1 }"#);
        assert_eq!(hits(r.rules, b"A\0"), vec!["one"]);
    }

    #[test]
    fn many_jumps_over_repeated_bytes_stay_fast() {
        let r = YaraRules::parse(
            "rule j { strings: $h = { 41 [0-1024] 41 [0-1024] 41 [0-1024] 42 } condition: $h }",
        );
        assert!(r.skipped.is_empty(), "{:?}", r.skipped);
        let started = std::time::Instant::now();
        let mut data = vec![b'A'; 8000];
        assert!(hits(r.rules.clone(), &data).is_empty());
        data.push(b'B');
        assert_eq!(hits(r.rules, &data), vec!["j"]);
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
    }

    #[test]
    fn hex_wildcards_jumps_and_lexing() {
        assert!(parse_hex("4D ?A [2] 00").is_ok());
        assert!(parse_hex("4D [2-] 00").is_err());
        assert!(parse_hex("( 4D | 5A )").is_err());
        assert!(parse_hex("[2] 00").is_err());
        let p = Pattern::Hex(parse_hex("41 ?2 [1-2] 43").unwrap());
        assert_eq!(p.matches(b"AB.C", true), Some(true));
        assert_eq!(p.matches(b"AR..C", true), Some(true));
        assert_eq!(p.matches(b"AX.C", true), Some(false));
        assert_eq!(p.matches(b"AB.", false), None);
        let (s, n) = lex_string(br#""a\x41\"b" rest"#).unwrap();
        assert_eq!((s.as_slice(), n), (&b"aA\"b"[..], 10));
    }

    #[test]
    fn a_broken_file_reports_instead_of_failing() {
        let p = YaraRules::parse("rule r { strings: $a = \"unterminated condition: $a }");
        assert!(p.rules.is_empty());
        assert_eq!(p.skipped.len(), 1);
    }
}
