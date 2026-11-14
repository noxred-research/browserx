//! Renders the accessibility tree as compact text with stable element references.
//!
//! Interactive elements get references (`e12`) keyed by their DOM backend node id, so the same
//! element keeps its number across snapshots until the page navigates. The reference table
//! remembers each element's role and name; interactions re-resolve the reference against the
//! live tree and refuse it when either changed.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::rc::Rc;

use serde_json::Value;

use super::snapshot::{Found, MAX_NODES, SnapLine};

/// Most references one page may hold; further elements are listed without one.
const MAX_REFS: u32 = 10_000;
/// Deepest nesting rendered.
pub(super) const MAX_DEPTH: usize = 40;
/// Longest accessible name rendered.
const MAX_NAME_CHARS: usize = 160;
/// Longest value rendered.
const MAX_VALUE_CHARS: usize = 120;

/// What a reference points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefInfo {
    /// DOM backend node id.
    pub backend: i64,
    /// Accessibility role at snapshot time.
    pub role: String,
    /// Accessible name at snapshot time (normalized).
    pub name: String,
}

/// The reference table of one page.
#[derive(Debug, Default)]
pub struct Refs {
    next: u32,
    by_backend: HashMap<i64, u32>,
    by_ref: HashMap<u32, RefInfo>,
}

impl Refs {
    /// Forgets every reference (the page navigated).
    pub fn clear(&mut self) {
        self.by_backend.clear();
        self.by_ref.clear();
    }

    /// The number of references held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_ref.len()
    }

    fn assign(&mut self, backend: i64, role: &str, name: &str) -> Option<u32> {
        let number = match self.by_backend.get(&backend) {
            Some(number) => *number,
            None => {
                if self.next >= MAX_REFS {
                    return None;
                }
                self.next += 1;
                self.by_backend.insert(backend, self.next);
                self.next
            }
        };
        self.by_ref.insert(
            number,
            RefInfo {
                backend,
                role: role.to_owned(),
                name: name.to_owned(),
            },
        );
        Some(number)
    }

    /// The element a reference was issued for.
    #[must_use]
    pub fn lookup(&self, number: u32) -> Option<&RefInfo> {
        self.by_ref.get(&number)
    }
}

/// Parses `e12`, `[e12]` or `ref=e12`.
#[must_use]
pub fn parse_ref(text: &str) -> Option<u32> {
    let trimmed = text
        .trim()
        .trim_start_matches("ref=")
        .trim_matches(|c| c == '[' || c == ']');
    let digits = trimmed
        .strip_prefix('e')
        .or_else(|| trimmed.strip_prefix('E'))?;
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

const INTERACTIVE_ROLES: [&str; 22] = [
    "button",
    "link",
    "textbox",
    "searchbox",
    "combobox",
    "checkbox",
    "radio",
    "switch",
    "slider",
    "spinbutton",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "tab",
    "option",
    "treeitem",
    "listbox",
    "ComboBoxSelect",
    "PopUpButton",
    "DisclosureTriangle",
    "ComboBoxMenuButton",
    "TextField",
];

const TRANSPARENT_ROLES: [&str; 9] = [
    "generic",
    "none",
    "presentation",
    "GenericContainer",
    "paragraph",
    "Section",
    "LayoutTable",
    "LayoutTableRow",
    "LayoutTableCell",
];

/// Collapses whitespace and bounds the length.
#[must_use]
pub fn normalize(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for word in text.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
        if out.chars().count() > max_chars {
            break;
        }
    }
    if out.chars().count() > max_chars {
        let mut clipped: String = out.chars().take(max_chars).collect();
        clipped.push('…');
        return clipped;
    }
    out
}

fn text_of<'a>(node: &'a Value, key: &str) -> &'a str {
    node.get(key)
        .and_then(|v| v.get("value"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

/// The role and normalized name of an accessibility node.
#[must_use]
pub fn role_and_name(node: &Value) -> (String, String) {
    (
        text_of(node, "role").to_owned(),
        normalize(text_of(node, "name"), MAX_NAME_CHARS),
    )
}

fn property<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
    node.get("properties")?
        .as_array()?
        .iter()
        .find(|p| p.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|p| p.get("value"))
        .and_then(|v| v.get("value"))
}

fn states(node: &Value) -> String {
    let mut out: Vec<String> = Vec::new();
    for flag in [
        "disabled", "required", "readonly", "focused", "invalid", "busy", "modal",
    ] {
        match property(node, flag) {
            Some(Value::Bool(true)) => out.push(flag.to_owned()),
            Some(Value::String(s)) if flag == "invalid" && s != "false" => {
                out.push(format!("invalid={s}"))
            }
            _ => {}
        }
    }
    for tri in ["checked", "pressed", "expanded", "selected"] {
        match property(node, tri) {
            Some(Value::Bool(b)) => out.push(format!("{tri}={b}")),
            Some(Value::String(s)) if s == "mixed" || s == "true" || s == "false" => {
                out.push(format!("{tri}={s}"));
            }
            _ => {}
        }
    }
    if let Some(level) = property(node, "level").and_then(Value::as_i64) {
        out.push(format!("level={level}"));
    }
    if let Some(Value::String(popup)) = property(node, "hasPopup")
        && popup != "false"
    {
        out.push(format!("haspopup={popup}"));
    }
    out.join(", ")
}

fn is_interactive(role: &str, node: &Value) -> bool {
    INTERACTIVE_ROLES.contains(&role)
        || (matches!(property(node, "focusable"), Some(Value::Bool(true)))
            && !matches!(
                role,
                "RootWebArea" | "WebArea" | "StaticText" | "generic" | "none"
            ))
}

/// A rendered snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The text (within the character budget).
    pub text: String,
    /// Title of the page (the root's name).
    pub title: String,
    /// Lines in `text`.
    pub lines: usize,
    /// References now live on the page.
    pub refs: usize,
    /// The text was cut at the character budget or the node cap.
    pub truncated: bool,
    /// Every rendered node, in order (at most [`MAX_NODES`]): the snapshot the diff works on.
    pub nodes: Vec<SnapLine>,
    /// Nodes rendered in all, including those past the node cap.
    pub total: usize,
    /// Nodes left out because the page hides them from users.
    pub hidden_omitted: usize,
}

/// Rendering options.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Character budget of the text.
    pub max_chars: usize,
    /// List only elements that carry references, flat.
    pub interactive_only: bool,
}

struct Pending<'a> {
    node: &'a Value,
    depth: usize,
    parent_name: Rc<str>,
    frame: Option<Rc<str>>,
}

#[derive(Default)]
struct Collector {
    nodes: Vec<SnapLine>,
    total: usize,
    synthetic: i64,
}

impl Collector {
    fn push(&mut self, key: Option<i64>, depth: usize, text: String, found: Option<Found>) {
        self.total += 1;
        if self.nodes.len() >= MAX_NODES {
            return;
        }
        let key = key.unwrap_or_else(|| {
            self.synthetic += 1;
            i64::MIN + self.synthetic
        });
        let reference = found.as_ref().map(|f| f.number);
        self.nodes.push(SnapLine {
            key,
            depth,
            text,
            reference,
            found,
        });
    }
}

/// Renders `nodes` (the `nodes` array of `Accessibility.getFullAXTree`, with the trees of
/// captured frames merged in by [`super::snapshot`]), assigning references. Nodes whose backend
/// id is in `hidden` are left out and counted.
#[must_use]
pub fn render(
    nodes: &[Value],
    refs: &mut Refs,
    options: Options,
    hidden: &HashSet<i64>,
) -> Rendered {
    let mut by_id: HashMap<&str, &Value> = HashMap::with_capacity(nodes.len());
    let mut children_of: HashSet<&str> = HashSet::new();
    for node in nodes {
        if let Some(id) = node.get("nodeId").and_then(Value::as_str) {
            by_id.insert(id, node);
        }
    }
    for node in nodes {
        for child in node
            .get("childIds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = child.as_str() {
                children_of.insert(id);
            }
        }
    }
    let roots: Vec<&Value> = nodes
        .iter()
        .filter(|n| {
            n.get("nodeId")
                .and_then(Value::as_str)
                .is_some_and(|id| !children_of.contains(id))
        })
        .collect();

    let mut out = Collector::default();
    let mut title = String::new();
    let mut hidden_omitted = 0usize;
    let mut stack: Vec<Pending<'_>> = roots
        .into_iter()
        .rev()
        .map(|node| Pending {
            node,
            depth: 0,
            parent_name: Rc::from(""),
            frame: None,
        })
        .collect();
    while let Some(Pending {
        node,
        depth,
        parent_name,
        frame,
    }) = stack.pop()
    {
        let ignored = node
            .get("ignored")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let (role, name) = role_and_name(node);
        let backend = node.get("backendDOMNodeId").and_then(Value::as_i64);
        let is_hidden = backend.is_some_and(|b| hidden.contains(&b));
        let mut child_depth = depth;
        let mut child_parent_name = Rc::clone(&parent_name);
        let mut child_frame = frame.clone();
        let mut descend = true;
        if !ignored && depth <= MAX_DEPTH {
            match role.as_str() {
                "InlineTextBox" | "LineBreak" => descend = false,
                "RootWebArea" | "WebArea" => {
                    if node.get("x_inline").is_some() {
                        // The content document of a frame: the frame line above stands for it.
                    } else {
                        if title.is_empty() {
                            title.clone_from(&name);
                        }
                        if !options.interactive_only {
                            out.push(backend, depth, format!("page \"{name}\""), None);
                        }
                        child_depth = depth + 1;
                    }
                }
                "StaticText" => {
                    descend = false;
                    let covered = !name.is_empty() && parent_name.contains(name.as_str());
                    if !name.is_empty() && !covered {
                        if is_hidden {
                            hidden_omitted += 1;
                        } else if !options.interactive_only {
                            out.push(backend, depth, format!("text \"{name}\""), None);
                        }
                    }
                }
                "Iframe" | "IframePresentational" if node.get("x_frame").is_some() => {
                    let info = &node["x_frame"];
                    let origin = info["origin"].as_str().unwrap_or("unknown");
                    let note = info["note"].as_str();
                    if is_hidden {
                        hidden_omitted += 1;
                    } else if note.is_some() || !options.interactive_only {
                        let mut line = format!("frame \"{origin}\"");
                        if let Some(note) = note {
                            let _ = write!(line, " ({note})");
                        }
                        out.push(backend, depth, line, None);
                    }
                    child_depth = depth + 1;
                    child_parent_name = Rc::from("");
                    child_frame = Some(Rc::from(origin));
                }
                r if TRANSPARENT_ROLES.contains(&r) || (r == "group" && name.is_empty()) => {}
                r => {
                    if is_hidden {
                        hidden_omitted += 1;
                    } else {
                        let found = if is_interactive(r, node) {
                            backend
                                .and_then(|b| refs.assign(b, r, &name))
                                .map(|number| Found {
                                    number,
                                    role: r.to_owned(),
                                    name: name.clone(),
                                    value: normalize(text_of(node, "value"), MAX_VALUE_CHARS),
                                    frame: frame.as_ref().map(|f| f.to_string()),
                                })
                        } else {
                            None
                        };
                        if found.is_some() || !options.interactive_only {
                            let mut line =
                                describe(r, &name, node, found.as_ref().map(|f| f.number));
                            if options.interactive_only
                                && let Some(origin) = &frame
                            {
                                let _ = write!(line, " (in frame \"{origin}\")");
                            }
                            out.push(backend, depth, line, found);
                        }
                    }
                    child_depth = depth + 1;
                    child_parent_name = Rc::from(name.as_str());
                }
            }
        } else if !ignored {
            descend = false;
        }
        if descend {
            let kids = node.get("childIds").and_then(Value::as_array);
            for child in kids.into_iter().flatten().rev() {
                if let Some(child) = child.as_str().and_then(|id| by_id.get(id)) {
                    stack.push(Pending {
                        node: child,
                        depth: if options.interactive_only {
                            0
                        } else {
                            child_depth
                        },
                        parent_name: Rc::clone(&child_parent_name),
                        frame: child_frame.clone(),
                    });
                }
            }
        }
    }
    let composed = compose(
        out.nodes.iter().map(|n| (n.depth, n.text.as_str())),
        out.total,
        options.max_chars,
        options.interactive_only,
    );
    Rendered {
        text: composed.text,
        title,
        lines: composed.shown,
        refs: refs.len(),
        truncated: composed.truncated,
        nodes: out.nodes,
        total: out.total,
        hidden_omitted,
    }
}

fn describe(role: &str, name: &str, node: &Value, reference: Option<u32>) -> String {
    let mut line = String::new();
    if let Some(number) = reference {
        let _ = write!(line, "[e{number}] ");
    }
    line.push_str(role);
    if !name.is_empty() {
        let _ = write!(line, " \"{name}\"");
    }
    let value = normalize(text_of(node, "value"), MAX_VALUE_CHARS);
    if !value.is_empty() {
        let _ = write!(line, " value=\"{value}\"");
    }
    let state = states(node);
    if !state.is_empty() {
        let _ = write!(line, " ({state})");
    }
    line
}

/// Text assembled from lines under a character budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composed {
    /// The text, notice included.
    pub text: String,
    /// Lines in it.
    pub shown: usize,
    /// Lines were left out.
    pub truncated: bool,
}

/// Joins `(depth, text)` lines into at most `max_chars` characters. `total` is how many lines
/// exist (it may exceed the lines given when the node cap was hit); the notice says how many were
/// not shown.
#[must_use]
pub fn compose<'a>(
    lines: impl Iterator<Item = (usize, &'a str)>,
    total: usize,
    max_chars: usize,
    interactive_only: bool,
) -> Composed {
    let mut text = String::new();
    let mut chars = 0usize;
    let mut shown = 0usize;
    let mut over_budget = false;
    for (depth, line) in lines {
        let indent = if interactive_only {
            0
        } else {
            depth.min(MAX_DEPTH) * 2
        };
        let needed = indent + line.chars().count() + 1;
        if chars + needed > max_chars {
            over_budget = true;
            break;
        }
        text.extend(std::iter::repeat_n(' ', indent));
        text.push_str(line);
        text.push('\n');
        chars += needed;
        shown += 1;
    }
    let missing = total.saturating_sub(shown);
    let truncated = missing > 0;
    if truncated {
        if over_budget {
            let _ = write!(
                text,
                "[truncated at {max_chars} characters: {missing} more nodes not shown; narrow with interactive_only/find_in_snapshot or raise max_chars]"
            );
        } else {
            let _ = write!(
                text,
                "[node cap reached: at most {MAX_NODES} nodes are kept per snapshot; {missing} more nodes not shown; narrow with interactive_only/find_in_snapshot]"
            );
        }
    }
    Composed {
        text,
        shown,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use serde_json::json;

    use super::*;

    fn node(id: &str, role: &str, name: &str, backend: i64, children: &[&str]) -> Value {
        json!({
            "nodeId": id, "ignored": false,
            "role": {"type": "role", "value": role},
            "name": {"type": "computedString", "value": name},
            "backendDOMNodeId": backend,
            "childIds": children,
        })
    }

    fn tree() -> Vec<Value> {
        let mut link = node("4", "link", "Cart", 14, &["5"]);
        link["properties"] =
            json!([{"name": "focusable", "value": {"type": "booleanOrUndefined", "value": true}}]);
        let mut input = node("6", "textbox", "Search", 16, &[]);
        input["value"] = json!({"type": "string", "value": "boots"});
        input["properties"] =
            json!([{"name": "required", "value": {"type": "boolean", "value": true}}]);
        let mut ignored = node("9", "generic", "", 19, &["10"]);
        ignored["ignored"] = json!(true);
        vec![
            node(
                "1",
                "RootWebArea",
                "Shop",
                11,
                &["2", "3", "4", "6", "7", "9"],
            ),
            node("2", "heading", "Welcome", 12, &["8"]),
            node("8", "StaticText", "Welcome", 18, &[]),
            node("3", "paragraph", "", 13, &["30"]),
            node("30", "StaticText", "Free shipping", 30, &[]),
            link,
            node("5", "StaticText", "Cart", 15, &[]),
            input,
            node("7", "button", "Add", 17, &[]),
            ignored,
            node("10", "button", "Hidden parent child", 20, &[]),
        ]
    }

    fn options(interactive_only: bool) -> Options {
        Options {
            max_chars: 4000,
            interactive_only,
        }
    }

    #[test]
    fn renders_roles_names_values_states_and_assigns_refs_to_interactive_nodes() {
        let mut refs = Refs::default();
        let out = render(&tree(), &mut refs, options(false), &HashSet::new());
        assert_eq!(out.title, "Shop");
        let expected = "page \"Shop\"\n  heading \"Welcome\"\n  text \"Free shipping\"\n  [e1] link \"Cart\"\n  \
                        [e2] textbox \"Search\" value=\"boots\" (required)\n  [e3] button \"Add\"\n  [e4] button \"Hidden parent child\"\n";
        assert_eq!(out.text, expected);
        assert_eq!(out.refs, 4);
        assert!(!out.truncated);
    }

    #[test]
    fn references_are_stable_across_snapshots_and_reset_on_clear() {
        let mut refs = Refs::default();
        let _ = render(&tree(), &mut refs, options(false), &HashSet::new());
        let mut reordered = tree();
        reordered.swap(5, 7);
        let again = render(&reordered, &mut refs, options(false), &HashSet::new());
        assert_eq!(refs.lookup(1).unwrap().role, "link");
        assert_eq!(refs.lookup(3).unwrap().name, "Add");
        assert_eq!(again.refs, 4);
        refs.clear();
        assert!(refs.lookup(1).is_none());
        assert_eq!(refs.len(), 0);
    }

    #[test]
    fn interactive_only_lists_just_referenced_elements() {
        let mut refs = Refs::default();
        let out = render(&tree(), &mut refs, options(true), &HashSet::new());
        assert_eq!(
            out.text,
            "[e1] link \"Cart\"\n[e2] textbox \"Search\" value=\"boots\" (required)\n[e3] button \"Add\"\n[e4] button \"Hidden parent child\"\n"
        );
    }

    #[test]
    fn budget_truncates_with_a_notice() {
        let mut refs = Refs::default();
        let out = render(
            &tree(),
            &mut refs,
            Options {
                max_chars: 60,
                interactive_only: false,
            },
            &HashSet::new(),
        );
        assert!(out.truncated);
        assert!(out.text.contains("truncated at 60 characters"));
    }

    #[test]
    fn parses_reference_spellings() {
        for good in ["e12", "E12", "[e12]", "ref=e12", " e12 "] {
            assert_eq!(parse_ref(good), Some(12), "{good}");
        }
        for bad in ["", "e", "12", "ex1", "e-1", "e1234567"] {
            assert_eq!(parse_ref(bad), None, "{bad}");
        }
    }

    #[test]
    fn names_are_normalized_and_bounded() {
        assert_eq!(normalize("  a \n b\t c ", 10), "a b c");
        assert!(normalize(&"x".repeat(500), 20).ends_with('…'));
    }
}
