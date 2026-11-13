//! Snapshot v2: per-tab snapshot store and deltas, frames with origin labels, hidden-text
//! detection and link collection.
//!
//! A snapshot is the accessibility tree of the main frame with the trees of same-process frames
//! merged in under their `Iframe` node, minus the nodes the page hides from users. Every
//! rendered node is kept (up to a cap) as a [`SnapLine`] keyed by its DOM backend node id, so a
//! later snapshot can be reported as a delta against it. Frames the browser keeps in another
//! process are listed but not read; frames whose origin the caller's filter refuses are replaced
//! by a placeholder and their text never reaches the output.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use serde_json::{Value, json};

use super::ax::{self, Options, normalize};
use super::conn::{Conn, TabRef};
use crate::error::{ToolError, ToolResult};

/// Most nodes kept per snapshot; a page with more is cut and marked truncated.
pub(super) const MAX_NODES: usize = 20_000;
/// Snapshots remembered per tab.
pub(super) const MAX_STORED: usize = 8;
/// Most frames read per snapshot.
const MAX_FRAMES: usize = 64;
/// Most DOM nodes `DOMSnapshot` may report before hidden-text detection is skipped.
const MAX_DOM_NODES: usize = 100_000;
/// Most links reported per snapshot.
const MAX_LINKS: usize = 2000;
/// Most removed refs listed in a delta.
const MAX_REMOVED_REFS: usize = 40;
/// Largest `find_in_snapshot` limit.
pub const MAX_FIND_LIMIT: usize = 100;

const NOTE_CROSS_PROCESS: &str = "content not captured: cross-process frame";
const NOTE_WITHHELD: &str = "content withheld: outside the read scope";
const NOTE_UNRESOLVED: &str = "content not captured: frame not resolved";
const NOTE_FRAME_LIMIT: &str = "content not captured: frame limit reached";

/// Says whether content of an origin (`https://host:port`) may be read. `Sync` so the futures
/// that borrow it can move between threads.
pub type ReadAllowed<'a> = &'a (dyn Fn(&str) -> bool + Sync);

/// What `find_in_snapshot` matches on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The reference number.
    pub number: u32,
    /// Accessibility role.
    pub role: String,
    /// Accessible name (normalized).
    pub name: String,
    /// Value (normalized).
    pub value: String,
    /// Origin of the frame the element sits in, when it is not the top-level page.
    pub frame: Option<String>,
}

/// One rendered node of a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapLine {
    /// DOM backend node id (a synthetic negative number when the node has none).
    pub key: i64,
    /// Nesting depth.
    pub depth: usize,
    /// The rendered line, without indentation.
    pub text: String,
    /// The element reference on the line.
    pub reference: Option<u32>,
    /// Match data of an element that has a reference.
    pub found: Option<Found>,
}

/// A remembered snapshot.
#[derive(Debug)]
pub(super) struct Stored {
    pub id: u64,
    pub interactive_only: bool,
    pub include_hidden: bool,
    /// The node cap cut the snapshot.
    pub capped: bool,
    pub nodes: Vec<SnapLine>,
}

/// The last few snapshots of one tab.
#[derive(Debug, Default)]
pub(super) struct SnapshotStore {
    next: u64,
    entries: VecDeque<Stored>,
}

impl SnapshotStore {
    /// Forgets every snapshot (the tab loaded a new document). Ids keep increasing.
    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }

    fn push(&mut self, mut stored: Stored) -> u64 {
        self.next += 1;
        stored.id = self.next;
        self.entries.push_back(stored);
        while self.entries.len() > MAX_STORED {
            self.entries.pop_front();
        }
        self.next
    }

    fn get(&self, id: u64) -> Option<&Stored> {
        self.entries.iter().find(|s| s.id == id)
    }

    fn latest(&self) -> Option<&Stored> {
        self.entries.back()
    }

    fn ids(&self) -> Vec<String> {
        self.entries.iter().map(|s| format!("s{}", s.id)).collect()
    }
}

/// Parses `s12`.
#[must_use]
pub fn parse_snapshot_id(text: &str) -> Option<u64> {
    let digits = text.trim().strip_prefix('s')?;
    if digits.is_empty() || digits.len() > 12 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// How two snapshots differ.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Delta {
    /// Indexes (in the new snapshot) of nodes that were not there before.
    pub added: Vec<usize>,
    /// Indexes of nodes whose line or depth changed.
    pub changed: Vec<usize>,
    /// Nodes that are gone.
    pub removed: usize,
    /// References the gone nodes carried.
    pub removed_refs: Vec<u32>,
    /// Nodes that are the same.
    pub unchanged: usize,
}

/// Compares two snapshots by node key.
#[must_use]
pub fn diff(old: &[SnapLine], new: &[SnapLine]) -> Delta {
    let mut before: HashMap<i64, &SnapLine> = HashMap::with_capacity(old.len());
    for line in old {
        before.entry(line.key).or_insert(line);
    }
    let mut delta = Delta::default();
    let mut seen: HashSet<i64> = HashSet::with_capacity(new.len());
    for (index, line) in new.iter().enumerate() {
        seen.insert(line.key);
        match before.get(&line.key) {
            None => delta.added.push(index),
            Some(prev) if prev.text != line.text || prev.depth != line.depth => {
                delta.changed.push(index);
            }
            Some(_) => delta.unchanged += 1,
        }
    }
    for line in old {
        if !seen.contains(&line.key) {
            delta.removed += 1;
            if let Some(reference) = line.reference {
                delta.removed_refs.push(reference);
            }
        }
    }
    delta.removed_refs.sort_unstable();
    delta.removed_refs.dedup();
    delta
}

/// Renders a delta: a removal summary, the unchanged count, then `+` (added) and `~` (changed)
/// lines in page order, indented by depth so the reader can place them.
#[must_use]
pub fn delta_text(
    delta: &Delta,
    new: &[SnapLine],
    interactive_only: bool,
    max_chars: usize,
) -> ax::Composed {
    let mut lines: Vec<String> = Vec::new();
    if delta.removed > 0 {
        let mut line = format!("- [removed] {} nodes", delta.removed);
        if !delta.removed_refs.is_empty() {
            let shown: Vec<String> = delta
                .removed_refs
                .iter()
                .take(MAX_REMOVED_REFS)
                .map(|n| format!("e{n}"))
                .collect();
            let _ = write!(line, " (refs: {}", shown.join(", "));
            if delta.removed_refs.len() > MAX_REMOVED_REFS {
                line.push_str(", …");
            }
            line.push(')');
        }
        lines.push(line);
    }
    lines.push(format!("{} unchanged nodes omitted", delta.unchanged));
    let mut order: Vec<(usize, char)> = delta
        .added
        .iter()
        .map(|i| (*i, '+'))
        .chain(delta.changed.iter().map(|i| (*i, '~')))
        .collect();
    order.sort_unstable();
    for (index, mark) in order {
        let Some(node) = new.get(index) else {
            continue;
        };
        let indent = if interactive_only {
            0
        } else {
            node.depth.min(ax::MAX_DEPTH) * 2
        };
        lines.push(format!("{mark} {}{}", " ".repeat(indent), node.text));
    }
    let total = lines.len();
    ax::compose(
        lines.iter().map(|l| (0, l.as_str())),
        total,
        max_chars,
        true,
    )
}

/// What a snapshot call asks for.
#[derive(Debug, Clone)]
pub struct SnapshotRequest {
    /// Character budget of the text.
    pub max_chars: usize,
    /// List only elements that carry references, flat.
    pub interactive_only: bool,
    /// Also list text the page hides from users.
    pub include_hidden: bool,
    /// Return only the delta against this snapshot id (`s3`).
    pub since: Option<String>,
}

/// Delta statistics of a snapshot taken with `since`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaStats {
    /// Nodes added.
    pub added: usize,
    /// Nodes changed.
    pub changed: usize,
    /// Nodes removed.
    pub removed: usize,
    /// Nodes unchanged (and omitted).
    pub unchanged: usize,
}

/// An accessibility snapshot.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// URL of the page.
    pub url: String,
    /// Title of the page.
    pub title: String,
    /// `s<N>`, increasing per tab.
    pub snapshot_id: String,
    /// The rendered text: the whole tree or, with `since`, the delta.
    pub text: String,
    /// Lines in `text`.
    pub lines: usize,
    /// References now live on the page.
    pub refs: usize,
    /// The text was cut (budget or node cap).
    pub truncated: bool,
    /// Present when `text` is a delta.
    pub delta: Option<DeltaStats>,
    /// `since` named a snapshot that is gone (or cannot be compared): the text is the full tree.
    pub since_unknown: bool,
    /// Why `since` could not be applied.
    pub since_note: Option<&'static str>,
    /// Nodes left out because the page hides them.
    pub hidden_omitted: usize,
    /// `ok`, `skipped_too_large` or `unavailable`.
    pub hidden_detection: &'static str,
    /// Frames whose content was read.
    pub frames: usize,
    /// Absolute http(s) URLs of `a[href]`, `area[href]` and `form[action]` in the captured
    /// frames, fragments stripped, deduplicated, at most 2000.
    pub links: Vec<String>,
}

/// What `find_in_snapshot` looks for.
#[derive(Debug, Clone)]
pub struct FindQuery {
    /// Case-insensitive substring of the accessible name or value.
    pub text: Option<String>,
    /// Accessibility role (case-insensitive).
    pub role: Option<String>,
    /// Most matches returned.
    pub limit: usize,
    /// Search this stored snapshot instead of the latest.
    pub snapshot_id: Option<String>,
}

/// The result of `find_in_snapshot`.
#[derive(Debug, Clone)]
pub struct FindResult {
    /// URL of the page.
    pub url: String,
    /// The snapshot searched.
    pub snapshot_id: String,
    /// A fresh snapshot was taken because the tab had none.
    pub fresh: bool,
    /// Matching lines (at most the limit).
    pub lines: Vec<String>,
    /// Elements that matched in all.
    pub matches: usize,
    /// More matched than are listed.
    pub truncated: bool,
}

/// Matches stored elements against a query.
#[must_use]
pub fn find(nodes: &[SnapLine], query: &FindQuery) -> (Vec<String>, usize) {
    let text = query.text.as_ref().map(|t| t.to_lowercase());
    let role = query.role.as_ref().map(|r| r.to_lowercase());
    let mut lines = Vec::new();
    let mut matches = 0usize;
    for node in nodes {
        let Some(found) = &node.found else {
            continue;
        };
        if let Some(role) = &role
            && found.role.to_lowercase() != *role
        {
            continue;
        }
        if let Some(text) = &text
            && !found.name.to_lowercase().contains(text.as_str())
            && !found.value.to_lowercase().contains(text.as_str())
        {
            continue;
        }
        matches += 1;
        if lines.len() < query.limit {
            let mut line = format!("[e{}] {}", found.number, found.role);
            if !found.name.is_empty() {
                let _ = write!(line, " \"{}\"", found.name);
            }
            if !found.value.is_empty() {
                let _ = write!(line, " value=\"{}\"", found.value);
            }
            if let Some(origin) = &found.frame {
                let _ = write!(line, " (in frame \"{origin}\")");
            }
            lines.push(line);
        }
    }
    (lines, matches)
}

/// The origin of a URL as the browser serializes it; `about:blank` for anything that is not
/// http(s).
#[must_use]
pub fn origin_of_url(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .map_or_else(
            || "about:blank".to_owned(),
            |u| u.origin().ascii_serialization(),
        )
}

// ---- hidden text and links ------------------------------------------------------------------

/// Computed styles requested from `DOMSnapshot.captureSnapshot`, in this order.
pub(super) const STYLES: [&str; 8] = [
    "display",
    "visibility",
    "opacity",
    "font-size",
    "color",
    "background-color",
    "overflow",
    "background-image",
];

/// Backend ids of hidden nodes and the links of the visible ones.
#[derive(Debug, Default)]
pub struct DomFacts {
    /// Nodes (elements and text) the page hides from users.
    pub hidden: HashSet<i64>,
    /// Absolute http(s) links.
    pub links: Vec<String>,
}

/// More DOM nodes than hidden detection will process.
#[derive(Debug, PartialEq, Eq)]
pub struct TooLarge;

#[derive(Clone, Copy, PartialEq)]
enum Bg {
    Known([u8; 3]),
    Unknown,
}

fn parse_color(text: &str) -> Option<([u8; 3], f32)> {
    let inner = text
        .strip_prefix("rgba(")
        .or_else(|| text.strip_prefix("rgb("))?
        .strip_suffix(')')?;
    let mut parts = inner.split(|c: char| c == ',' || c == '/' || c.is_whitespace());
    let mut next = || {
        parts
            .by_ref()
            .find(|p| !p.is_empty())
            .and_then(|p| p.parse::<f32>().ok())
    };
    let (r, g, b) = (next()?, next()?, next()?);
    let a = next().unwrap_or(1.0);
    let byte = |v: f32| v.clamp(0.0, 255.0).round() as u8;
    Some(([byte(r), byte(g), byte(b)], a))
}

fn parse_px(text: &str) -> Option<f32> {
    text.strip_suffix("px")?.parse().ok()
}

fn near(a: [u8; 3], b: [u8; 3]) -> bool {
    a.iter().zip(b).all(|(x, y)| x.abs_diff(y) <= 3)
}

fn int_at(value: &Value, key: &str, at: usize) -> Option<i64> {
    value.get(key)?.as_array()?.get(at)?.as_i64()
}

/// Works out which nodes of a `DOMSnapshot.captureSnapshot` result are hidden from users and
/// which links the visible ones carry. `frame_read(frame_id)` tells whether a document's frame
/// was captured (links of other frames are not reported). With `include_hidden`, links of hidden
/// elements are kept.
///
/// A node is hidden when it, or an ancestor that clips or fades it, has a zero-size clipped box,
/// opacity 0, `aria-hidden="true"` or sits wholly beyond -1000px off the document; or when it
/// itself has `visibility` other than visible, a font size under 1px, or text colour (nearly)
/// equal to the effective background (nearest ancestor with an opaque background colour, white
/// by default).
///
/// # Errors
/// [`TooLarge`] when the snapshot has more than 100 000 DOM nodes.
pub fn dom_facts(
    snapshot: &Value,
    include_hidden: bool,
    frame_read: &dyn Fn(&str) -> bool,
) -> Result<DomFacts, TooLarge> {
    let strings: Vec<&str> = snapshot["strings"]
        .as_array()
        .map(|a| a.iter().map(|s| s.as_str().unwrap_or("")).collect())
        .unwrap_or_default();
    let string_at = |index: i64| -> &str {
        usize::try_from(index)
            .ok()
            .and_then(|i| strings.get(i))
            .copied()
            .unwrap_or("")
    };
    let documents: &[Value] = snapshot["documents"].as_array().map_or(&[], Vec::as_slice);
    let total: usize = documents
        .iter()
        .map(|d| d["nodes"]["parentIndex"].as_array().map_or(0, Vec::len))
        .sum();
    if total > MAX_DOM_NODES {
        return Err(TooLarge);
    }

    // Parents before children: the document tree is walked from the first document.
    let mut order: Vec<usize> = Vec::with_capacity(documents.len());
    let mut visited = vec![false; documents.len()];
    let mut queue: VecDeque<usize> = VecDeque::new();
    if !documents.is_empty() {
        queue.push_back(0);
        visited[0] = true;
    }
    while let Some(k) = queue.pop_front() {
        order.push(k);
        let owned = &documents[k]["nodes"]["contentDocumentIndex"];
        for value in owned["value"].as_array().into_iter().flatten() {
            if let Some(child) = value.as_u64().and_then(|v| usize::try_from(v).ok())
                && child < documents.len()
                && !visited[child]
            {
                visited[child] = true;
                queue.push_back(child);
            }
        }
    }
    for (k, seen) in visited.iter().enumerate() {
        if !seen {
            order.push(k);
        }
    }

    let mut facts = DomFacts::default();
    let mut link_seen: HashSet<String> = HashSet::new();
    let mut initial: Vec<bool> = vec![false; documents.len()];
    for k in order {
        let doc = &documents[k];
        let nodes = &doc["nodes"];
        let parents = nodes["parentIndex"]
            .as_array()
            .map_or(&[][..], Vec::as_slice);
        let count = parents.len();
        let frame_id = string_at(doc["frameId"].as_i64().unwrap_or(-1));
        let read_links = frame_read(frame_id);
        let base = {
            let base = string_at(doc["baseURL"].as_i64().unwrap_or(-1));
            let base = if base.is_empty() {
                string_at(doc["documentURL"].as_i64().unwrap_or(-1))
            } else {
                base
            };
            url::Url::parse(base).ok()
        };
        let mut row_of: Vec<Option<usize>> = vec![None; count];
        for (row, index) in doc["layout"]["nodeIndex"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            if let Some(i) = index.as_u64().and_then(|i| usize::try_from(i).ok())
                && i < count
            {
                row_of[i] = Some(row);
            }
        }
        let owner_of: HashMap<usize, usize> = {
            let owned = &nodes["contentDocumentIndex"];
            let index = owned["index"].as_array().map_or(&[][..], Vec::as_slice);
            let value = owned["value"].as_array().map_or(&[][..], Vec::as_slice);
            index
                .iter()
                .zip(value)
                .filter_map(|(i, v)| {
                    Some((
                        usize::try_from(i.as_u64()?).ok()?,
                        usize::try_from(v.as_u64()?).ok()?,
                    ))
                })
                .collect()
        };
        let styles_rows = doc["layout"]["styles"].as_array();
        let bounds_rows = doc["layout"]["bounds"].as_array();
        let mut subtree_hidden = vec![false; count];
        let mut bg = vec![Bg::Known([255, 255, 255]); count];
        for i in 0..count {
            let parent = parents[i]
                .as_i64()
                .and_then(|p| usize::try_from(p).ok())
                .filter(|p| *p < i);
            let mut inherited = parent.map_or(initial[k], |p| subtree_hidden[p]);
            let mut background = parent.map_or(Bg::Known([255, 255, 255]), |p| bg[p]);
            let node_type = int_at(nodes, "nodeType", i).unwrap_or(0);
            let attrs: &[Value] = nodes["attributes"]
                .get(i)
                .and_then(Value::as_array)
                .map_or(&[], Vec::as_slice);
            let attr = |wanted: &str| -> Option<&str> {
                attrs.chunks(2).find_map(|pair| {
                    let name = string_at(pair.first()?.as_i64()?);
                    name.eq_ignore_ascii_case(wanted)
                        .then(|| string_at(pair.get(1).and_then(Value::as_i64).unwrap_or(-1)))
                })
            };
            let mut own_subtree = node_type == 1 && attr("aria-hidden") == Some("true");
            let mut own_leaf = false;
            if let Some(row) = row_of[i] {
                let style = |at: usize| -> &str {
                    styles_rows
                        .and_then(|rows| rows.get(row))
                        .and_then(Value::as_array)
                        .and_then(|cells| cells.get(at))
                        .and_then(Value::as_i64)
                        .map_or("", string_at)
                };
                let bounds: Vec<f64> = bounds_rows
                    .and_then(|rows| rows.get(row))
                    .and_then(Value::as_array)
                    .map(|b| b.iter().map(|v| v.as_f64().unwrap_or(0.0)).collect())
                    .unwrap_or_default();
                let (visibility, opacity, font_size, color, back, overflow, image) = (
                    style(1),
                    style(2),
                    style(3),
                    style(4),
                    style(5),
                    style(6),
                    style(7),
                );
                if let [x, y, w, h] = bounds[..] {
                    if node_type == 3 && (w <= 0.0 || h <= 0.0) {
                        own_leaf = true;
                    }
                    if node_type == 1 {
                        let clipped = !matches!(overflow, "" | "visible");
                        if clipped && (w <= 0.0 || h <= 0.0 || (w <= 1.0 && h <= 1.0)) {
                            own_subtree = true;
                        }
                    }
                    if x + w < -1000.0 || y + h < -1000.0 {
                        own_subtree = true;
                    }
                }
                if opacity.parse::<f32>().is_ok_and(|o| o <= 0.01) {
                    own_subtree = true;
                }
                if !visibility.is_empty() && visibility != "visible" {
                    own_leaf = true;
                }
                if parse_px(font_size).is_some_and(|px| px < 1.0) {
                    own_leaf = true;
                }
                if let Some((rgb, alpha)) = parse_color(back)
                    && alpha >= 0.9
                {
                    background = Bg::Known(rgb);
                } else if !image.is_empty() && image != "none" {
                    background = Bg::Unknown;
                }
                if let Some((rgb, alpha)) = parse_color(color) {
                    if alpha < 0.05 {
                        own_leaf = true;
                    } else if let Bg::Known(under) = background
                        && near(rgb, under)
                    {
                        own_leaf = true;
                    }
                }
            }
            inherited |= own_subtree;
            subtree_hidden[i] = inherited;
            bg[i] = background;
            let hidden = inherited || own_leaf;
            let backend = int_at(nodes, "backendNodeId", i);
            if hidden && let Some(backend) = backend {
                facts.hidden.insert(backend);
            }
            if let Some(child) = owner_of.get(&i)
                && *child < initial.len()
            {
                initial[*child] = hidden;
            }
            if read_links
                && node_type == 1
                && facts.links.len() < MAX_LINKS
                && (include_hidden || !hidden)
            {
                let name = string_at(int_at(nodes, "nodeName", i).unwrap_or(-1));
                let target = if name.eq_ignore_ascii_case("a") || name.eq_ignore_ascii_case("area")
                {
                    attr("href")
                } else if name.eq_ignore_ascii_case("form") {
                    attr("action")
                } else {
                    None
                };
                if let (Some(target), Some(base)) = (target, &base)
                    && let Ok(mut link) = base.join(target.trim())
                    && matches!(link.scheme(), "http" | "https")
                {
                    link.set_fragment(None);
                    let link = link.to_string();
                    if link_seen.insert(link.clone()) {
                        facts.links.push(link);
                    }
                }
            }
        }
    }
    Ok(facts)
}

// ---- frames ---------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct FrameInfo {
    origin: String,
}

fn frame_origin(frame: &Value) -> String {
    let secure = frame["securityOrigin"].as_str().unwrap_or("");
    let origin = if secure.is_empty() || secure == "null" || secure == "://" {
        origin_of_url(frame["url"].as_str().unwrap_or(""))
    } else {
        secure.to_owned()
    };
    normalize(&origin, 200)
}

fn collect_frames(tree: &Value, out: &mut HashMap<String, FrameInfo>) {
    if let Some(id) = tree["frame"]["id"].as_str() {
        out.insert(
            id.to_owned(),
            FrameInfo {
                origin: frame_origin(&tree["frame"]),
            },
        );
    }
    for child in tree["childFrames"].as_array().into_iter().flatten() {
        collect_frames(child, out);
    }
}

/// Why a frame's content is not read: the filter refuses its origin, or the browser keeps it
/// out of reach (`readable` false). `None` means the content may be read.
fn frame_note(read_allowed: ReadAllowed<'_>, origin: &str, readable: bool) -> Option<&'static str> {
    if !read_allowed(origin) {
        Some(NOTE_WITHHELD)
    } else if !readable {
        Some(NOTE_CROSS_PROCESS)
    } else {
        None
    }
}

fn is_iframe_node(node: &Value) -> bool {
    matches!(
        node["role"]["value"].as_str(),
        Some("Iframe" | "IframePresentational")
    ) && node["ignored"].as_bool() != Some(true)
}

/// What one snapshot captured before rendering.
struct Captured {
    url: String,
    nodes: Vec<Value>,
    hidden: HashSet<i64>,
    hidden_detection: &'static str,
    links: Vec<String>,
    frames: usize,
}

impl Conn {
    async fn capture(
        &self,
        tab: &TabRef,
        include_hidden: bool,
        read_allowed: ReadAllowed<'_>,
    ) -> ToolResult<Captured> {
        let url = self.current_url(tab).await?;
        let page_origin = origin_of_url(&url);
        if !read_allowed(&page_origin) {
            return Err(ToolError::refused(format!(
                "the page's origin {page_origin} is outside the read scope"
            )));
        }
        self.scope
            .check_final(&url)
            .map_err(|r| ToolError::refused(r.0))?;

        let tree = self
            .call(tab, "Accessibility.getFullAXTree", json!({}))
            .await?;
        let mut nodes: Vec<Value> = tree["nodes"].as_array().cloned().unwrap_or_default();
        let mut known: HashMap<String, FrameInfo> = HashMap::new();
        let mut main_frame: Option<String> = None;
        if let Ok(frames) = self.call(tab, "Page.getFrameTree", json!({})).await {
            main_frame = frames["frameTree"]["frame"]["id"]
                .as_str()
                .map(str::to_owned);
            collect_frames(&frames["frameTree"], &mut known);
        }
        let mut targets: Option<HashMap<String, String>> = None;
        let mut captured: HashSet<String> = main_frame.into_iter().collect();
        let mut frames_read = 0usize;
        let mut resolved = 0usize;
        let mut index = 0usize;
        while index < nodes.len() {
            if !is_iframe_node(&nodes[index]) {
                index += 1;
                continue;
            }
            let backend = nodes[index]["backendDOMNodeId"].as_i64();
            let mut label = json!({ "origin": "unknown", "note": NOTE_UNRESOLVED });
            let mut attach: Option<(String, Vec<Value>)> = None;
            if resolved >= MAX_FRAMES {
                label["note"] = json!(NOTE_FRAME_LIMIT);
            } else if let Some(backend) = backend {
                resolved += 1;
                let frame_id = self
                    .call(tab, "DOM.describeNode", json!({ "backendNodeId": backend }))
                    .await
                    .ok()
                    .and_then(|d| d["node"]["frameId"].as_str().map(str::to_owned));
                if let Some(frame_id) = frame_id {
                    if let Some(info) = known.get(&frame_id) {
                        label["origin"] = json!(info.origin);
                        if let Some(note) = frame_note(read_allowed, &info.origin, true) {
                            label["note"] = json!(note);
                        } else {
                            match self
                                .call(
                                    tab,
                                    "Accessibility.getFullAXTree",
                                    json!({ "frameId": frame_id }),
                                )
                                .await
                            {
                                Ok(sub) => {
                                    label["note"] = Value::Null;
                                    attach = Some((
                                        frame_id,
                                        sub["nodes"].as_array().cloned().unwrap_or_default(),
                                    ));
                                }
                                Err(_) => label["note"] = json!(NOTE_UNRESOLVED),
                            }
                        }
                    } else {
                        if targets.is_none() {
                            targets = Some(self.iframe_targets().await);
                        }
                        let origin = targets
                            .as_ref()
                            .and_then(|t| t.get(&frame_id))
                            .map(|u| normalize(&origin_of_url(u), 200));
                        if let Some(origin) = origin {
                            label["note"] = json!(frame_note(read_allowed, &origin, false));
                            label["origin"] = json!(origin);
                        } else {
                            label["note"] = json!(NOTE_CROSS_PROCESS);
                        }
                    }
                }
            }
            nodes[index]["x_frame"] = label;
            if let Some((frame_id, sub)) = attach {
                frames_read += 1;
                captured.insert(frame_id);
                let prefix = format!("f{frames_read}:");
                merge_frame(&mut nodes, index, &prefix, sub);
            }
            index += 1;
        }

        let mut hidden = HashSet::new();
        let mut links = Vec::new();
        let mut hidden_detection = "unavailable";
        if let Ok(snapshot) = self
            .call(
                tab,
                "DOMSnapshot.captureSnapshot",
                json!({ "computedStyles": STYLES }),
            )
            .await
        {
            match dom_facts(&snapshot, include_hidden, &|id| captured.contains(id)) {
                Ok(facts) => {
                    hidden_detection = "ok";
                    if !include_hidden {
                        hidden = facts.hidden;
                    }
                    links = facts.links;
                }
                Err(TooLarge) => hidden_detection = "skipped_too_large",
            }
        }
        Ok(Captured {
            url,
            nodes,
            hidden,
            hidden_detection,
            links,
            frames: frames_read,
        })
    }

    /// Frame targets the browser keeps in another process: id to URL.
    async fn iframe_targets(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        if let Ok(reply) = self.browser_call("Target.getTargets", json!({})).await {
            for info in reply["targetInfos"].as_array().into_iter().flatten() {
                if info["type"] == "iframe"
                    && let (Some(id), Some(url)) = (info["targetId"].as_str(), info["url"].as_str())
                {
                    out.insert(id.to_owned(), url.to_owned());
                }
            }
        }
        out
    }

    /// Takes a snapshot: renders it, remembers it and, with `since`, reports the delta.
    ///
    /// `read_allowed(origin)` says whether content of an origin may be read: the page's own
    /// origin must pass it, and frames of other origins are replaced by a placeholder.
    ///
    /// # Errors
    /// When the page is outside the scope or read filter, `since` is malformed, or the browser
    /// fails.
    pub async fn snapshot(
        &self,
        tab: &TabRef,
        request: &SnapshotRequest,
        read_allowed: ReadAllowed<'_>,
    ) -> ToolResult<Snapshot> {
        let since =
            match request.since.as_deref() {
                None => None,
                Some(text) => Some(parse_snapshot_id(text).ok_or_else(|| {
                    ToolError::invalid("`since` must be a snapshot_id such as s3")
                })?),
            };
        let captured = self
            .capture(tab, request.include_hidden, read_allowed)
            .await?;
        self.finish_snapshot(tab, request, since, captured)
    }

    fn finish_snapshot(
        &self,
        tab: &TabRef,
        request: &SnapshotRequest,
        since: Option<u64>,
        captured: Captured,
    ) -> ToolResult<Snapshot> {
        let mut state = self.shared.state();
        let tab_state = state
            .tab_mut(tab.num)
            .ok_or_else(|| ToolError::browser("the tab went away"))?;
        let mut rendered = ax::render(
            &captured.nodes,
            &mut tab_state.refs,
            Options {
                max_chars: request.max_chars,
                interactive_only: request.interactive_only,
            },
            &captured.hidden,
        );
        let capped = rendered.total > rendered.nodes.len();
        let mut text = std::mem::take(&mut rendered.text);
        let mut lines = rendered.lines;
        let mut truncated = rendered.truncated;
        let mut delta = None;
        let mut since_unknown = false;
        let mut since_note = None;
        if let Some(wanted) = since {
            match tab_state.snaps.get(wanted) {
                None => since_unknown = true,
                Some(old)
                    if old.interactive_only != request.interactive_only
                        || old.include_hidden != request.include_hidden =>
                {
                    since_unknown = true;
                    since_note = Some(
                        "the earlier snapshot used different interactive_only or include_hidden options",
                    );
                }
                Some(old) if old.capped || capped => {
                    since_unknown = true;
                    since_note = Some("a snapshot hit the node cap, so it cannot be compared");
                }
                Some(old) => {
                    let changes = diff(&old.nodes, &rendered.nodes);
                    let composed = delta_text(
                        &changes,
                        &rendered.nodes,
                        request.interactive_only,
                        request.max_chars,
                    );
                    delta = Some(DeltaStats {
                        added: changes.added.len(),
                        changed: changes.changed.len(),
                        removed: changes.removed,
                        unchanged: changes.unchanged,
                    });
                    text = composed.text;
                    lines = composed.shown;
                    truncated = composed.truncated;
                }
            }
        }
        let id = tab_state.snaps.push(Stored {
            id: 0,
            interactive_only: request.interactive_only,
            include_hidden: request.include_hidden,
            capped,
            nodes: std::mem::take(&mut rendered.nodes),
        });
        Ok(Snapshot {
            url: captured.url,
            title: rendered.title,
            snapshot_id: format!("s{id}"),
            text,
            lines,
            refs: rendered.refs,
            truncated,
            delta,
            since_unknown,
            since_note,
            hidden_omitted: rendered.hidden_omitted,
            hidden_detection: captured.hidden_detection,
            frames: captured.frames,
            links: captured.links,
        })
    }

    /// Searches a stored snapshot of the tab (the latest unless `snapshot_id` names one),
    /// taking a fresh one when the tab has none.
    ///
    /// # Errors
    /// When the snapshot id is malformed or unknown, or taking a snapshot fails.
    pub async fn find_in_snapshot(
        &self,
        tab: &TabRef,
        query: &FindQuery,
        read_allowed: ReadAllowed<'_>,
    ) -> ToolResult<FindResult> {
        let wanted = match query.snapshot_id.as_deref() {
            None => None,
            Some(text) => Some(
                parse_snapshot_id(text)
                    .ok_or_else(|| ToolError::invalid("`snapshot_id` must look like s3"))?,
            ),
        };
        let stored = {
            let state = self.shared.state();
            let tab_state = state
                .tab(tab.num)
                .ok_or_else(|| ToolError::browser("the tab went away"))?;
            let entry = match wanted {
                Some(id) => Some(tab_state.snaps.get(id).ok_or_else(|| {
                    ToolError::invalid(format!(
                        "snapshot s{id} is unknown or was evicted (this tab keeps {}: {})",
                        MAX_STORED,
                        tab_state.snaps.ids().join(", ")
                    ))
                })?),
                None => tab_state.snaps.latest(),
            };
            entry.map(|s| {
                let (lines, matches) = find(&s.nodes, query);
                (format!("s{}", s.id), lines, matches)
            })
        };
        let (snapshot_id, lines, matches, fresh) = match stored {
            Some((id, lines, matches)) => (id, lines, matches, false),
            None => {
                let request = SnapshotRequest {
                    max_chars: 500,
                    interactive_only: true,
                    include_hidden: false,
                    since: None,
                };
                let snap = self.snapshot(tab, &request, read_allowed).await?;
                let state = self.shared.state();
                let tab_state = state
                    .tab(tab.num)
                    .ok_or_else(|| ToolError::browser("the tab went away"))?;
                let id = parse_snapshot_id(&snap.snapshot_id).unwrap_or(0);
                let (lines, matches) = tab_state
                    .snaps
                    .get(id)
                    .map_or((Vec::new(), 0), |s| find(&s.nodes, query));
                (snap.snapshot_id, lines, matches, true)
            }
        };
        let url = self.current_url(tab).await?;
        Ok(FindResult {
            url,
            snapshot_id,
            fresh,
            truncated: matches > lines.len(),
            lines,
            matches,
        })
    }
}

/// Appends a frame's nodes under the `Iframe` node at `at`, prefixing ids so they stay unique.
/// Returns the id of the frame's root.
fn merge_frame(
    nodes: &mut Vec<Value>,
    at: usize,
    prefix: &str,
    mut sub: Vec<Value>,
) -> Option<String> {
    let mut child_ids: HashSet<String> = HashSet::new();
    for node in &sub {
        for child in node["childIds"].as_array().into_iter().flatten() {
            if let Some(id) = child.as_str() {
                child_ids.insert(id.to_owned());
            }
        }
    }
    let mut root: Option<String> = None;
    for node in &mut sub {
        let Some(id) = node["nodeId"].as_str().map(str::to_owned) else {
            continue;
        };
        if root.is_none() && !child_ids.contains(&id) {
            root = Some(format!("{prefix}{id}"));
            node["x_inline"] = json!(true);
        }
        node["nodeId"] = json!(format!("{prefix}{id}"));
        if let Some(kids) = node["childIds"].as_array_mut() {
            for kid in kids.iter_mut() {
                if let Some(kid_id) = kid.as_str() {
                    *kid = json!(format!("{prefix}{kid_id}"));
                }
            }
        }
    }
    nodes.extend(sub);
    let root_id = root.clone()?;
    let parent = nodes.get_mut(at)?;
    match parent["childIds"].as_array_mut() {
        Some(kids) => kids.push(json!(root_id)),
        None => parent["childIds"] = json!([root_id]),
    }
    root
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn line(key: i64, depth: usize, text: &str, reference: Option<u32>) -> SnapLine {
        SnapLine {
            key,
            depth,
            text: text.to_owned(),
            reference,
            found: reference.map(|number| Found {
                number,
                role: "button".into(),
                name: text.to_owned(),
                value: String::new(),
                frame: None,
            }),
        }
    }

    #[test]
    fn diff_reports_added_changed_removed_and_unchanged_by_node_key() {
        let old = vec![
            line(1, 0, "page \"A\"", None),
            line(2, 1, "[e1] button \"Add\"", Some(1)),
            line(3, 1, "text \"x\"", None),
            line(4, 1, "[e2] link \"Gone\"", Some(2)),
        ];
        let new = vec![
            line(1, 0, "page \"A\"", None),
            line(2, 1, "[e1] button \"Added\"", Some(1)),
            line(3, 2, "text \"x\"", None),
            line(5, 1, "text \"new\"", None),
        ];
        let d = diff(&old, &new);
        assert_eq!(d.added, vec![3]);
        assert_eq!(d.changed, vec![1, 2]);
        assert_eq!(d.removed, 1);
        assert_eq!(d.removed_refs, vec![2]);
        assert_eq!(d.unchanged, 1);
        let text = delta_text(&d, &new, false, 4000).text;
        assert!(text.contains("- [removed] 1 nodes (refs: e2)"), "{text}");
        assert!(text.contains("1 unchanged nodes omitted"));
        assert!(text.contains("~   [e1] button \"Added\""), "{text}");
        assert!(text.contains("~     text \"x\""));
        assert!(text.contains("+   text \"new\""));
        assert!(!text.contains("page \"A\""));
    }

    #[test]
    fn store_keeps_the_last_eight_and_clear_keeps_counting() {
        let mut store = SnapshotStore::default();
        for _ in 0..10 {
            store.push(Stored {
                id: 0,
                interactive_only: false,
                include_hidden: false,
                capped: false,
                nodes: Vec::new(),
            });
        }
        assert!(store.get(2).is_none());
        assert!(store.get(3).is_some());
        assert_eq!(store.latest().unwrap().id, 10);
        assert_eq!(store.ids().len(), MAX_STORED);
        store.clear();
        assert!(store.latest().is_none());
        let next = store.push(Stored {
            id: 0,
            interactive_only: false,
            include_hidden: false,
            capped: false,
            nodes: Vec::new(),
        });
        assert_eq!(next, 11);
    }

    #[test]
    fn snapshot_ids_parse_strictly() {
        assert_eq!(parse_snapshot_id("s12"), Some(12));
        for bad in ["", "s", "12", "S1", "s-1", "s1x", "s1234567890123"] {
            assert_eq!(parse_snapshot_id(bad), None, "{bad}");
        }
    }

    #[test]
    fn find_matches_name_or_value_and_role_and_honors_the_limit() {
        let mut a = line(1, 0, "Add to cart", Some(1));
        a.found.as_mut().unwrap().name = "Add to cart".into();
        let mut b = line(2, 0, "Search", Some(2));
        {
            let f = b.found.as_mut().unwrap();
            f.role = "textbox".into();
            f.name = "Search".into();
            f.value = "red BOOTS".into();
            f.frame = Some("https://x.test".into());
        }
        let mut c = line(3, 0, "Add more", Some(3));
        c.found.as_mut().unwrap().name = "Add more".into();
        let plain = line(4, 0, "text \"Add\"", None);
        let nodes = vec![a, b, c, plain];
        let ask = |text: Option<&str>, role: Option<&str>, limit| {
            find(
                &nodes,
                &FindQuery {
                    text: text.map(str::to_owned),
                    role: role.map(str::to_owned),
                    limit,
                    snapshot_id: None,
                },
            )
        };
        let (lines, matches) = ask(Some("ADD"), None, 20);
        assert_eq!(matches, 2);
        assert_eq!(
            lines,
            vec!["[e1] button \"Add to cart\"", "[e3] button \"Add more\""]
        );
        let (lines, _) = ask(Some("boots"), Some("TextBox"), 20);
        assert_eq!(
            lines,
            vec!["[e2] textbox \"Search\" value=\"red BOOTS\" (in frame \"https://x.test\")"]
        );
        let (lines, matches) = ask(None, Some("button"), 1);
        assert_eq!((lines.len(), matches), (1, 2));
    }

    /// One document: strings are indexed through `s`.
    fn synthetic() -> Value {
        let mut strings: Vec<String> = Vec::new();
        let mut s = |text: &str| -> i64 {
            if let Some(i) = strings.iter().position(|t| t == text) {
                return i64::try_from(i).unwrap();
            }
            strings.push(text.to_owned());
            i64::try_from(strings.len() - 1).unwrap()
        };
        let mut style =
            |opacity: &str, size: &str, color: &str, back: &str, overflow: &str| -> Vec<i64> {
                [
                    "block", "visible", opacity, size, color, back, overflow, "none",
                ]
                .iter()
                .map(|t| s(t))
                .collect()
            };
        let black = "rgb(0, 0, 0)";
        let clear = "rgba(0, 0, 0, 0)";
        let white = "rgb(255, 255, 255)";
        let dark = "rgb(20, 20, 20)";
        // index: 0 doc, 1 html, 2 body, 3 p normal, 4 text, 5 p tiny font, 6 text, 7 p opacity 0,
        // 8 text, 9 p white-on-white, 10 text, 11 p aria-hidden, 12 text, 13 p off-screen,
        // 14 text, 15 a (visible link), 16 a hidden link (opacity 0), 17 div dark bg,
        // 18 text white on dark, 19 div clipped 0x0 overflow hidden, 20 text in it
        let rows: Vec<(usize, Vec<i64>, [f64; 4])> = vec![
            (
                1,
                style("1", "16px", black, clear, "visible"),
                [0.0, 0.0, 800.0, 600.0],
            ),
            (
                2,
                style("1", "16px", black, clear, "visible"),
                [8.0, 8.0, 784.0, 500.0],
            ),
            (
                3,
                style("1", "16px", black, clear, "visible"),
                [8.0, 8.0, 784.0, 18.0],
            ),
            (
                4,
                style("1", "16px", black, clear, "visible"),
                [8.0, 8.0, 50.0, 18.0],
            ),
            (
                5,
                style("1", "0px", black, clear, "visible"),
                [8.0, 30.0, 784.0, 0.0],
            ),
            (
                6,
                style("1", "0px", black, clear, "visible"),
                [8.0, 30.0, 0.0, 0.0],
            ),
            (
                7,
                style("0", "16px", black, clear, "visible"),
                [8.0, 40.0, 784.0, 18.0],
            ),
            (
                8,
                style("1", "16px", black, clear, "visible"),
                [8.0, 40.0, 50.0, 18.0],
            ),
            (
                9,
                style("1", "16px", white, white, "visible"),
                [8.0, 60.0, 784.0, 18.0],
            ),
            (
                10,
                style("1", "16px", white, white, "visible"),
                [8.0, 60.0, 50.0, 18.0],
            ),
            (
                11,
                style("1", "16px", black, clear, "visible"),
                [8.0, 80.0, 784.0, 18.0],
            ),
            (
                12,
                style("1", "16px", black, clear, "visible"),
                [8.0, 80.0, 50.0, 18.0],
            ),
            (
                13,
                style("1", "16px", black, clear, "visible"),
                [-5000.0, 100.0, 80.0, 18.0],
            ),
            (
                14,
                style("1", "16px", black, clear, "visible"),
                [-5000.0, 100.0, 80.0, 18.0],
            ),
            (
                15,
                style("1", "16px", black, clear, "visible"),
                [8.0, 120.0, 30.0, 18.0],
            ),
            (
                16,
                style("0", "16px", black, clear, "visible"),
                [8.0, 140.0, 30.0, 18.0],
            ),
            (
                17,
                style("1", "16px", white, dark, "visible"),
                [8.0, 160.0, 300.0, 30.0],
            ),
            (
                18,
                style("1", "16px", white, dark, "visible"),
                [8.0, 160.0, 100.0, 30.0],
            ),
            (
                19,
                style("1", "16px", black, clear, "hidden"),
                [8.0, 200.0, 0.0, 0.0],
            ),
            (
                20,
                style("1", "16px", black, clear, "hidden"),
                [8.0, 200.0, 10.0, 10.0],
            ),
        ];
        let parents = [
            -1, 0, 1, 2, 3, 2, 5, 2, 7, 2, 9, 2, 11, 2, 13, 2, 2, 2, 17, 2, 19,
        ];
        let types = [
            9, 1, 1, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 1, 1, 3, 1, 3,
        ];
        let names = [
            "#document",
            "HTML",
            "BODY",
            "P",
            "#text",
            "P",
            "#text",
            "P",
            "#text",
            "P",
            "#text",
            "P",
            "#text",
            "P",
            "#text",
            "A",
            "A",
            "DIV",
            "#text",
            "DIV",
            "#text",
        ];
        let name_idx: Vec<i64> = names.iter().map(|n| s(n)).collect();
        let aria = s("aria-hidden");
        let truthy = s("true");
        let href = s("href");
        let rel = s("/shop#top");
        let hid = s("/secret");
        let attributes: Vec<Vec<i64>> = (0..21)
            .map(|i| match i {
                11 => vec![aria, truthy],
                15 => vec![href, rel],
                16 => vec![href, hid],
                _ => vec![],
            })
            .collect();
        let backend: Vec<i64> = (0..21).map(|i| 100 + i).collect();
        let layout_nodes: Vec<usize> = std::iter::once(0).chain(rows.iter().map(|r| r.0)).collect();
        let mut styles: Vec<Vec<i64>> = vec![vec![]];
        let mut bounds: Vec<Vec<f64>> = vec![vec![0.0, 0.0, 800.0, 600.0]];
        for (_, st, b) in &rows {
            styles.push(st.clone());
            bounds.push(b.to_vec());
        }
        let doc_url = s("https://shop.test/index");
        let frame = s("F0");
        json!({
            "strings": strings,
            "documents": [{
                "documentURL": doc_url, "baseURL": doc_url, "frameId": frame,
                "nodes": {
                    "parentIndex": parents, "nodeType": types, "nodeName": name_idx,
                    "backendNodeId": backend, "attributes": attributes,
                    "contentDocumentIndex": {"index": [], "value": []},
                },
                "layout": {"nodeIndex": layout_nodes, "styles": styles, "bounds": bounds},
            }],
        })
    }

    #[test]
    fn hidden_nodes_are_found_from_a_dom_snapshot_and_links_come_from_visible_elements() {
        let facts = dom_facts(&synthetic(), false, &|_| true).unwrap();
        let hidden_backends: Vec<i64> = {
            let mut v: Vec<i64> = facts.hidden.iter().copied().collect();
            v.sort_unstable();
            v
        };
        // tiny font (p 105 and its text 106), opacity 0 (107, 108), white on white (109, 110),
        // aria-hidden (111, 112), off-screen (113, 114), the opacity-0 link (116), the clipped
        // 0x0 container (119, 120).
        assert_eq!(
            hidden_backends,
            vec![
                105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 116, 119, 120
            ]
        );
        // visible: the normal paragraph, the visible link, white text on a dark background.
        for visible in [103, 104, 115, 117, 118] {
            assert!(!facts.hidden.contains(&visible), "{visible}");
        }
        assert_eq!(facts.links, vec!["https://shop.test/shop".to_owned()]);
        let with_hidden = dom_facts(&synthetic(), true, &|_| true).unwrap();
        assert_eq!(
            with_hidden.links,
            vec![
                "https://shop.test/shop".to_owned(),
                "https://shop.test/secret".to_owned()
            ]
        );
        let none = dom_facts(&synthetic(), false, &|_| false).unwrap();
        assert!(none.links.is_empty());
        assert!(!none.hidden.is_empty());
    }

    #[test]
    fn hidden_detection_refuses_huge_snapshots() {
        let big = json!({
            "strings": [],
            "documents": [{"nodes": {"parentIndex": vec![-1; MAX_DOM_NODES + 1]}}],
        });
        assert_eq!(dom_facts(&big, false, &|_| true).unwrap_err(), TooLarge);
    }

    #[test]
    fn colors_parse_and_compare_with_a_small_tolerance() {
        assert_eq!(parse_color("rgb(1, 2, 3)"), Some(([1, 2, 3], 1.0)));
        assert_eq!(parse_color("rgba(1, 2, 3, 0.5)"), Some(([1, 2, 3], 0.5)));
        assert_eq!(parse_color("color(srgb 1 1 1)"), None);
        assert!(near([255, 255, 255], [254, 253, 255]));
        assert!(!near([255, 255, 255], [240, 240, 240]));
    }

    #[test]
    fn frames_merge_under_their_iframe_node_with_unique_ids() {
        let mut nodes = vec![
            json!({"nodeId": "1", "childIds": ["2"], "role": {"value": "RootWebArea"}}),
            json!({"nodeId": "2", "childIds": [], "role": {"value": "Iframe"}}),
        ];
        let sub = vec![
            json!({"nodeId": "1", "childIds": ["2"], "role": {"value": "RootWebArea"}}),
            json!({"nodeId": "2", "childIds": [], "role": {"value": "button"}}),
        ];
        let root = merge_frame(&mut nodes, 1, "f1:", sub).unwrap();
        assert_eq!(root, "f1:1");
        assert_eq!(nodes[1]["childIds"], json!(["f1:1"]));
        assert_eq!(nodes[2]["x_inline"], json!(true));
        assert_eq!(nodes[2]["childIds"], json!(["f1:2"]));
        assert_eq!(nodes[3]["nodeId"], json!("f1:2"));
    }

    #[test]
    fn origins_come_from_the_security_origin_or_the_url() {
        assert_eq!(
            frame_origin(&json!({"securityOrigin": "https://a.test", "url": "https://b.test/x"})),
            "https://a.test"
        );
        assert_eq!(
            frame_origin(&json!({"securityOrigin": "null", "url": "https://b.test:8443/x"})),
            "https://b.test:8443"
        );
        assert_eq!(origin_of_url("about:srcdoc"), "about:blank");
    }

    #[test]
    fn frame_notes_follow_the_filter_before_reachability() {
        assert_eq!(frame_note(&|_| true, "https://a.test", true), None);
        assert_eq!(
            frame_note(&|_| true, "https://a.test", false),
            Some(NOTE_CROSS_PROCESS)
        );
        assert_eq!(
            frame_note(&|o| o != "https://a.test", "https://a.test", true),
            Some(NOTE_WITHHELD)
        );
        assert_eq!(
            frame_note(&|_| false, "https://a.test", false),
            Some(NOTE_WITHHELD)
        );
    }

    #[test]
    fn a_withheld_frame_renders_as_a_placeholder_and_its_text_never_appears() {
        let mut nodes = vec![
            json!({"nodeId": "1", "childIds": ["2"], "role": {"value": "RootWebArea"}, "name": {"value": "Top"}, "backendDOMNodeId": 1}),
            json!({"nodeId": "2", "childIds": [], "role": {"value": "Iframe"}, "backendDOMNodeId": 2,
                   "x_frame": {"origin": "https://other.test", "note": NOTE_WITHHELD}}),
        ];
        let mut refs = ax::Refs::default();
        let options = Options {
            max_chars: 4000,
            interactive_only: false,
        };
        let out = ax::render(&nodes, &mut refs, options, &HashSet::new());
        assert_eq!(
            out.text,
            "page \"Top\"\n  frame \"https://other.test\" (content withheld: outside the read scope)\n"
        );
        // A captured frame: labelled, nested, refs inside it carry the origin when flat.
        nodes[1]["x_frame"] = json!({"origin": "https://same.test", "note": null});
        let sub = vec![
            json!({"nodeId": "1", "childIds": ["2"], "role": {"value": "RootWebArea"}, "name": {"value": "Inner"}, "backendDOMNodeId": 10}),
            json!({"nodeId": "2", "childIds": [], "role": {"value": "button"}, "name": {"value": "Go"}, "backendDOMNodeId": 11}),
        ];
        merge_frame(&mut nodes, 1, "f1:", sub);
        let out = ax::render(&nodes, &mut refs, options, &HashSet::new());
        assert_eq!(
            out.text,
            "page \"Top\"\n  frame \"https://same.test\"\n    [e1] button \"Go\"\n"
        );
        let flat = ax::render(
            &nodes,
            &mut refs,
            Options {
                interactive_only: true,
                ..options
            },
            &HashSet::new(),
        );
        assert_eq!(
            flat.text,
            "[e1] button \"Go\" (in frame \"https://same.test\")\n"
        );
        // Hidden nodes are skipped and counted; the count only includes what would show.
        let hidden: HashSet<i64> = [11].into();
        let out = ax::render(&nodes, &mut refs, options, &hidden);
        assert_eq!(out.hidden_omitted, 1);
        assert!(!out.text.contains("Go"));
    }

    #[test]
    fn truncation_counts_the_nodes_it_did_not_show() {
        let mut nodes = vec![
            json!({"nodeId": "r", "childIds": [], "role": {"value": "RootWebArea"}, "name": {"value": "T"}}),
        ];
        let ids: Vec<String> = (0..50).map(|i| format!("n{i}")).collect();
        nodes[0]["childIds"] = json!(ids);
        for (i, id) in ids.iter().enumerate() {
            nodes.push(
                json!({"nodeId": id, "childIds": [], "role": {"value": "heading"},
                "name": {"value": format!("Heading number {i}")}, "backendDOMNodeId": i + 1}),
            );
        }
        let mut refs = ax::Refs::default();
        let out = ax::render(
            &nodes,
            &mut refs,
            Options {
                max_chars: 200,
                interactive_only: false,
            },
            &HashSet::new(),
        );
        assert!(out.truncated);
        assert_eq!(out.total, 51);
        assert_eq!(out.nodes.len(), 51, "the diff still sees every node");
        let missing = 51 - out.lines;
        assert!(
            out.text.contains(&format!(
                "[truncated at 200 characters: {missing} more nodes not shown; narrow with interactive_only/find_in_snapshot or raise max_chars]"
            )),
            "{}",
            out.text
        );
    }

    /// The real browser: frames, the read filter, links.
    mod live {
        use std::process::{Child, Command, Stdio};
        use std::sync::Arc;
        use std::time::Duration;

        use serde_json::Value;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        use super::super::*;
        use crate::browse::Limits;
        use crate::config::Window;
        use crate::safety::Scope;

        struct Browser(Child);

        impl Drop for Browser {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        async fn serve(listener: TcpListener, port_a: u16, port_b: u16) {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 4096];
                    let n = stream.read(&mut buffer).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buffer[..n]).into_owned();
                    let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    let body = match path.as_str() {
                        "/" => format!(
                            "<h1>Top page</h1><a href=\"/next#frag\">Next</a>\
                             <iframe src=\"http://127.0.0.1:{port_b}/same-site\" title=\"a\"></iframe>\
                             <iframe src=\"http://localhost:{port_a}/cross\" title=\"b\"></iframe>"
                        ),
                        "/same-site" => {
                            "<h2>FRAME-SECRET</h2><a href=\"/leak\">leak</a>".to_owned()
                        }
                        "/cross" => "<h2>CROSS-SECRET</h2>".to_owned(),
                        _ => "<p>other</p>".to_owned(),
                    };
                    let page = format!("<!doctype html><title>t</title><body>{body}");
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                                page.len()
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = stream.shutdown().await;
                });
            }
        }

        fn free_port() -> u16 {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        }

        #[tokio::test]
        async fn the_read_filter_withholds_frames_and_their_links_in_a_real_browser() {
            let Some(exe) = browserx_runtime::discover_chromium() else {
                eprintln!("SKIP: no Chromium found (set BROWSERX_CHROMIUM_PATH)");
                return;
            };
            let dir = tempfile::tempdir().unwrap();
            let debug_port = free_port();
            let child = Command::new(exe)
                .args([
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-gpu",
                    &format!("--remote-debugging-port={debug_port}"),
                    &format!("--user-data-dir={}", dir.path().display()),
                    "about:blank",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let _browser = Browser(child);
            let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (pa, pb) = (
                a.local_addr().unwrap().port(),
                b.local_addr().unwrap().port(),
            );
            tokio::spawn(serve(a, pa, pb));
            tokio::spawn(serve(b, pa, pb));

            let version_url = format!("http://127.0.0.1:{debug_port}/json/version");
            let mut ws = None;
            for _ in 0..100 {
                if let Ok(reply) = reqwest::get(&version_url).await
                    && let Ok(value) = reply.json::<Value>().await
                    && let Some(url) = value["webSocketDebuggerUrl"].as_str()
                {
                    ws = Some(url.to_owned());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let ws = ws.expect("the browser did not start");
            let scope = Arc::new(Scope::new(Vec::new(), false, Window::default()));
            let conn = Conn::connect(&ws, Limits::default(), scope).await.unwrap();
            let tab = conn.tab(None).await.unwrap();
            conn.navigate(&tab, &format!("http://127.0.0.1:{pa}/"))
                .await
                .unwrap();
            // Frames load after the main document: give them a moment.
            tokio::time::sleep(Duration::from_millis(500)).await;

            let request = SnapshotRequest {
                max_chars: 20_000,
                interactive_only: false,
                include_hidden: false,
                since: None,
            };
            let same_site = format!("http://127.0.0.1:{pb}");
            let cross_site = format!("http://localhost:{pa}");

            let all = conn.snapshot(&tab, &request, &|_| true).await.unwrap();
            assert!(
                all.text.contains(&format!("frame \"{same_site}\"\n")),
                "{}",
                all.text
            );
            assert!(all.text.contains("FRAME-SECRET"), "{}", all.text);
            assert!(!all.text.contains("CROSS-SECRET"), "{}", all.text);
            assert!(
                all.text.contains(&format!(
                    "frame \"{cross_site}\" (content not captured: cross-process frame)"
                )),
                "{}",
                all.text
            );
            assert!(all.links.contains(&format!("http://127.0.0.1:{pa}/next")));
            assert!(
                all.links.contains(&format!("{same_site}/leak")),
                "{:?}",
                all.links
            );

            let denied = conn
                .snapshot(&tab, &request, &|o| o != same_site)
                .await
                .unwrap();
            assert!(
                denied.text.contains(&format!(
                    "frame \"{same_site}\" (content withheld: outside the read scope)"
                )),
                "{}",
                denied.text
            );
            assert!(!denied.text.contains("FRAME-SECRET"), "{}", denied.text);
            assert!(
                !denied.links.iter().any(|l| l.contains("/leak")),
                "{:?}",
                denied.links
            );
            assert!(
                denied
                    .links
                    .contains(&format!("http://127.0.0.1:{pa}/next"))
            );

            let no_cross = conn
                .snapshot(&tab, &request, &|o| o != cross_site)
                .await
                .unwrap();
            assert!(
                no_cross.text.contains(&format!(
                    "frame \"{cross_site}\" (content withheld: outside the read scope)"
                )),
                "{}",
                no_cross.text
            );

            let page_origin = format!("http://127.0.0.1:{pa}");
            let refused = conn
                .snapshot(&tab, &request, &|o| o != page_origin)
                .await
                .unwrap_err();
            assert!(
                refused.to_string().contains("outside the read scope"),
                "{refused}"
            );
            conn.close().await;
        }
    }
}
