//! The fixed scripts the server runs inside pages. None of them takes model-written code.

/// Converts the main content of the page to Markdown. Call as `(PAGE_TEXT)(maxChars)`; it
/// returns `{title, url, text, truncated}`.
///
/// The conversion prefers `main`, `article` or `[role=main]`, otherwise the body without
/// navigation, sidebars and footers; hidden elements are skipped; link targets are kept, image
/// sources are not (alt text only); the output stops at `maxChars`.
pub const PAGE_TEXT: &str = r#"(function (maxChars) {
  var out = [];
  var size = 0;
  var truncated = false;
  var SKIP = {SCRIPT:1, STYLE:1, NOSCRIPT:1, TEMPLATE:1, SVG:1, CANVAS:1, IFRAME:1, OBJECT:1, EMBED:1, HEAD:1, LINK:1, META:1, AUDIO:1, VIDEO:1};
  var CHROME = {NAV:1, ASIDE:1, FOOTER:1};
  var BLOCK = {ADDRESS:1, ARTICLE:1, ASIDE:1, BLOCKQUOTE:1, DETAILS:1, DIV:1, DL:1, DT:1, DD:1, FIELDSET:1, FIGCAPTION:1, FIGURE:1, FOOTER:1, FORM:1, H1:1, H2:1, H3:1, H4:1, H5:1, H6:1, HEADER:1, HR:1, LI:1, MAIN:1, NAV:1, OL:1, P:1, PRE:1, SECTION:1, SUMMARY:1, TABLE:1, UL:1, TR:1};
  var useChrome = false;
  function push(block) {
    if (truncated || !block) { return; }
    if (size + block.length > maxChars) {
      block = block.slice(0, Math.max(0, maxChars - size));
      truncated = true;
    }
    out.push(block);
    size += block.length + 2;
  }
  function hidden(el) {
    if (el.hidden || el.getAttribute('aria-hidden') === 'true') { return true; }
    var style = window.getComputedStyle(el);
    return style.display === 'none' || style.visibility === 'hidden';
  }
  function absolute(href) {
    try { return new URL(href, document.baseURI).href; } catch (e) { return href; }
  }
  function skip(el) {
    if (SKIP[el.tagName] || hidden(el)) { return true; }
    if (useChrome) {
      var role = el.getAttribute('role');
      if (CHROME[el.tagName] || role === 'navigation' || role === 'banner' || role === 'contentinfo') { return true; }
    }
    return false;
  }
  function inline(node) {
    if (node.nodeType === 3) { return node.nodeValue.replace(/\s+/g, ' '); }
    if (node.nodeType !== 1 || skip(node)) { return ''; }
    var tag = node.tagName;
    if (tag === 'BR') { return '\n'; }
    if (tag === 'IMG') {
      var alt = node.getAttribute('alt');
      return alt ? '![' + alt.trim() + ']' : '';
    }
    var inner = '';
    for (var child = node.firstChild; child; child = child.nextSibling) { inner += inline(child); }
    var trimmed = inner.trim();
    if (!trimmed) { return inner; }
    if (tag === 'A') {
      var href = node.getAttribute('href');
      return href && href.indexOf('javascript:') !== 0 ? '[' + trimmed + '](' + absolute(href) + ')' : inner;
    }
    if (tag === 'STRONG' || tag === 'B') { return '**' + trimmed + '**'; }
    if (tag === 'EM' || tag === 'I') { return '*' + trimmed + '*'; }
    if (tag === 'CODE') { return '`' + trimmed + '`'; }
    return inner;
  }
  function flow(node, prefix) {
    var buffer = '';
    function flush() {
      var text = buffer.replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
      if (text) { push(prefix + text); }
      buffer = '';
    }
    for (var child = node.firstChild; child && !truncated; child = child.nextSibling) {
      if (child.nodeType === 1 && BLOCK[child.tagName]) {
        flush();
        block(child, prefix);
      } else {
        buffer += inline(child);
      }
    }
    flush();
  }
  function list(el, depth) {
    var ordered = el.tagName === 'OL';
    var index = 0;
    for (var item = el.firstElementChild; item && !truncated; item = item.nextElementSibling) {
      if (item.tagName !== 'LI' || skip(item)) { continue; }
      index += 1;
      var marker = ordered ? index + '. ' : '- ';
      var pad = new Array(depth + 1).join('  ');
      var text = '';
      var nested = [];
      for (var child = item.firstChild; child; child = child.nextSibling) {
        if (child.nodeType === 1 && (child.tagName === 'UL' || child.tagName === 'OL')) { nested.push(child); }
        else { text += inline(child); }
      }
      push(pad + marker + text.replace(/\s+/g, ' ').trim());
      for (var i = 0; i < nested.length; i++) { list(nested[i], depth + 1); }
    }
  }
  function table(el) {
    var rows = el.querySelectorAll('tr');
    var wroteHeader = false;
    for (var r = 0; r < rows.length && !truncated; r++) {
      var cells = rows[r].querySelectorAll('th,td');
      var texts = [];
      for (var c = 0; c < cells.length; c++) { texts.push(inline(cells[c]).replace(/\s+/g, ' ').replace(/\|/g, '\\|').trim()); }
      if (!texts.length) { continue; }
      push('| ' + texts.join(' | ') + ' |');
      if (!wroteHeader && rows[r].querySelector('th')) {
        push('|' + texts.map(function () { return ' --- |'; }).join(''));
        wroteHeader = true;
      }
    }
  }
  function block(el, prefix) {
    if (truncated || skip(el)) { return; }
    var tag = el.tagName;
    if (/^H[1-6]$/.test(tag)) {
      var heading = inline(el).replace(/\s+/g, ' ').trim();
      if (heading) { push(prefix + new Array(Number(tag.charAt(1)) + 1).join('#') + ' ' + heading); }
    } else if (tag === 'UL' || tag === 'OL') {
      list(el, 0);
    } else if (tag === 'PRE') {
      push(prefix + '```\n' + el.textContent.replace(/\n+$/, '') + '\n```');
    } else if (tag === 'BLOCKQUOTE') {
      flow(el, prefix + '> ');
    } else if (tag === 'TABLE') {
      table(el);
    } else if (tag === 'HR') {
      push('---');
    } else {
      flow(el, prefix);
    }
  }
  var root = document.querySelector('main, article, [role="main"]');
  if (!root) { root = document.body; useChrome = true; }
  if (root) { block(root, ''); }
  return { title: document.title || '', url: location.href, text: out.join('\n\n'), truncated: truncated };
})"#;

/// Reads the visible text of the document body.
pub const BODY_HAS_TEXT: &str = r#"(function (needle) {
  return !!document.body && document.body.innerText.indexOf(needle) !== -1;
})"#;

/// Selects the option of a `<select>` by value or label. Returns `{ok, label, value}` or
/// `{ok:false, options}`.
pub const SELECT_OPTION: &str = r#"function (value, label) {
  if (this.tagName !== 'SELECT') { return {ok: false, error: 'the element is not a select'}; }
  var options = Array.prototype.slice.call(this.options);
  var match = null;
  for (var i = 0; i < options.length && !match; i++) {
    if ((value !== null && options[i].value === value) ||
        (label !== null && options[i].label.trim() === label.trim())) { match = options[i]; }
  }
  if (!match) {
    return {ok: false, options: options.slice(0, 50).map(function (o) { return o.label.trim(); })};
  }
  if (match.disabled) { return {ok: false, error: 'the option is disabled'}; }
  this.value = match.value;
  this.dispatchEvent(new Event('input', {bubbles: true}));
  this.dispatchEvent(new Event('change', {bubbles: true}));
  return {ok: true, label: match.label.trim(), value: match.value};
}"#;

/// Selects the content of an input, textarea or editable element so typing replaces it.
pub const SELECT_CONTENT: &str = r#"function () {
  if (typeof this.select === 'function') { this.select(); return true; }
  if (this.isContentEditable) {
    var range = document.createRange();
    range.selectNodeContents(this);
    var selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    return true;
  }
  return false;
}"#;

/// The scroll position and extent of the page.
pub const SCROLL_STATE: &str = "({x: Math.round(window.scrollX), y: Math.round(window.scrollY), \
width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight, \
viewportWidth: window.innerWidth, viewportHeight: window.innerHeight})";
