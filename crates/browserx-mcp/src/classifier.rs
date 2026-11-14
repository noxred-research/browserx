//! The deterministic action classification gate: pure logic, no I/O, no model.
//!
//! Before the server acts on an element it collects [`Features`] of the element (its role, its
//! accessible name, the form it submits, the URL it opens) and asks [`classify`] what kind of
//! action the model is about to take. [`decide`] then maps the class and the engagement profile
//! to a [`Decision`]. Models advise; this table decides.
//!
//! # Semantics
//!
//! * The class is the **maximum severity** ([`ActionClass::severity`]) over all evidence, from
//!   structure (what the control does) and from language (what its label and URL say).
//!   Evidence never lowers a class: when sources disagree, the stricter class wins.
//! * A label never *lowers* risk. A control labelled "Cancel" that submits a POST form to
//!   `/account/delete` is [`ActionClass::Destructive`].
//! * A label *raises* risk only together with structural evidence that the control acts: it is
//!   a submit control of a non-GET form (or carries a `formaction`), or it is a plain actuator
//!   (a button or menu item with no form and no `href`, whose effect is unknown and is
//!   therefore read the strict way). A lexicon label on a real link to an in-scope page stays a
//!   navigation, unless the URL path itself hits the destructive lexicon (`/logout`,
//!   `/delete`): a GET with side effects.
//! * Links: `mailto:`, `tel:` and `sms:` are external communication; `javascript:` is
//!   [`ActionClass::Unknown`]; a `download` attribute or an archive or binary file extension is a
//!   file transfer; otherwise the caller's scope check decides between in-scope and
//!   out-of-scope navigation. A link that only points into the current document (`#top`) is an
//!   in-page anchor that scripts commonly hijack, so its label is read like an actuator's.
//! * Fields: password inputs and `current-password`, `new-password` and `one-time-code`
//!   autocomplete tokens are credential entry; `cc-*` tokens are payment; so are fields whose
//!   label or `id`/`name` says password or card number. Any text field of a form that contains
//!   a password input is credential entry too. File inputs are file transfer.
//! * Forms: a submit (a submit button or image input, Enter in a field of a form, or typing with
//!   `submit`) in a GET form is a navigation (out of scope when the action's origin is outside
//!   the scope). In a POST, PUT, PATCH or DELETE form it is a state change, raised by a form
//!   that carries a password (credential entry), a file input (file transfer), an out-of-scope
//!   action (external communication: the data leaves the scope) and by the action path and the
//!   control label (destructive, payment, external communication, credential entry). An action
//!   that submits is classified by the submission only: the edit it carries is part of it.
//! * Enter: on a link or button it is a click; in a form field it submits the form; in a
//!   field with no form it may be a script's "send" key and is [`ActionClass::Unknown`];
//!   elsewhere it is a read.
//! * Plain actuators with no evidence at all are [`ActionClass::Unknown`]. Controls inside
//!   frames the page embeds are [`ActionClass::Unknown`].
//! * `disabled` is informational: a disabled control is classified as if it were enabled.
//!
//! The multilingual lexicon below is intentionally small. It is a static table of folded words
//! (lower case, accents removed) matched as whole words (a trailing `*` makes the last word a
//! prefix) on the tokens of a label or URL path, and as substrings for scripts that do not
//! separate words. Extend it by adding a row; the vectors in `tests/vectors/classifier` pin the
//! behavior across implementations.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

/// Longest label, id or name considered, in characters.
const MAX_TEXT_CHARS: usize = 512;
/// Longest URL considered, in characters.
const MAX_URL_CHARS: usize = 2048;

/// What kind of thing an action does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    /// Looking or expanding: no state of the application changes.
    Read,
    /// Navigating to a page inside the actuation scope.
    NavigateInScope,
    /// Navigating to a page outside the actuation scope.
    NavigateOutOfScope,
    /// Editing a field or choosing an option, without submitting.
    FormEdit,
    /// Submitting a form that changes server state.
    SubmitStateChange,
    /// Entering or submitting credentials.
    CredentialEntry,
    /// Sending something to a person or publishing it (data leaves the scope).
    ExternalCommunication,
    /// Deleting, deactivating, revoking or ending a session.
    Destructive,
    /// Spending money.
    Payment,
    /// Uploading or downloading a file.
    FileTransfer,
    /// The effect cannot be determined; read as the stricter option.
    Unknown,
}

impl ActionClass {
    /// Every class.
    pub const ALL: [Self; 11] = [
        Self::Read,
        Self::NavigateInScope,
        Self::NavigateOutOfScope,
        Self::FormEdit,
        Self::SubmitStateChange,
        Self::CredentialEntry,
        Self::ExternalCommunication,
        Self::Destructive,
        Self::Payment,
        Self::FileTransfer,
        Self::Unknown,
    ];

    /// The stable snake_case name (the one used in serialized form).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::NavigateInScope => "navigate_in_scope",
            Self::NavigateOutOfScope => "navigate_out_of_scope",
            Self::FormEdit => "form_edit",
            Self::SubmitStateChange => "submit_state_change",
            Self::CredentialEntry => "credential_entry",
            Self::ExternalCommunication => "external_communication",
            Self::Destructive => "destructive",
            Self::Payment => "payment",
            Self::FileTransfer => "file_transfer",
            Self::Unknown => "unknown",
        }
    }

    /// The class named `name`, if any.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.name() == name)
    }

    /// How strict the class is; higher is stricter. Evidence is merged by taking the maximum.
    /// The order never makes [`decide`] less strict as severity grows, for any profile.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::NavigateInScope => 1,
            Self::FormEdit => 2,
            Self::SubmitStateChange => 3,
            Self::Unknown => 4,
            Self::CredentialEntry => 5,
            Self::FileTransfer => 6,
            Self::ExternalCommunication => 7,
            Self::Destructive => 8,
            Self::NavigateOutOfScope => 9,
            Self::Payment => 10,
        }
    }
}

/// How much the engagement lets the agent do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Look and navigate inside the scope; nothing else.
    ReadOnly,
    /// A test environment the operator owns: state changes are allowed, risky actions need
    /// approval, spending money and leaving the scope are denied.
    TestEnvironment,
    /// An authorized security test. Today the table equals the test environment's; it stays a
    /// separate profile so deployments can diverge.
    AuthorizedSecurityTest,
}

impl Profile {
    /// Every profile.
    pub const ALL: [Self; 3] = [
        Self::ReadOnly,
        Self::TestEnvironment,
        Self::AuthorizedSecurityTest,
    ];
}

/// What the gate does with an action. Ordered by strictness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Proceed.
    Allow,
    /// Proceed only with the operator's approval.
    Approval,
    /// Refuse.
    Deny,
}

/// The decision for `class` under `profile`.
#[must_use]
pub fn decide(profile: Profile, class: ActionClass) -> Decision {
    use ActionClass as C;
    use Decision as D;
    match profile {
        Profile::ReadOnly => match class {
            C::Read | C::NavigateInScope => D::Allow,
            _ => D::Deny,
        },
        Profile::TestEnvironment => match class {
            C::Read | C::NavigateInScope | C::FormEdit | C::SubmitStateChange => D::Allow,
            C::CredentialEntry
            | C::ExternalCommunication
            | C::Destructive
            | C::FileTransfer
            | C::Unknown => D::Approval,
            C::NavigateOutOfScope | C::Payment => D::Deny,
        },
        // The profile with the most privilege: a control whose effect cannot be seen (a plain
        // script button) may be used; everything that leaves the application or is hard to
        // undo still needs an approval.
        Profile::AuthorizedSecurityTest => match class {
            C::Read | C::NavigateInScope | C::FormEdit | C::SubmitStateChange | C::Unknown => {
                D::Allow
            }
            C::CredentialEntry | C::ExternalCommunication | C::Destructive | C::FileTransfer => {
                D::Approval
            }
            C::NavigateOutOfScope | C::Payment => D::Deny,
        },
    }
}

/// The whole decision table, profile by profile in declaration order and class by class in
/// [`ActionClass::ALL`] order.
#[must_use]
pub fn table() -> Vec<(Profile, ActionClass, Decision)> {
    let mut rows = Vec::with_capacity(Profile::ALL.len() * ActionClass::ALL.len());
    for profile in Profile::ALL {
        for class in ActionClass::ALL {
            rows.push((profile, class, decide(profile, class)));
        }
    }
    rows
}

/// The stricter of two decisions.
#[must_use]
pub fn stricter(a: Decision, b: Decision) -> Decision {
    a.max(b)
}

/// How the model is about to act on the element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Intent {
    /// Click the element.
    Click,
    /// Type into the element, then optionally press Enter.
    TypeText {
        /// Whether Enter follows the text.
        submit: bool,
    },
    /// Choose an option of a select element.
    SelectOption,
    /// Press Enter with the element focused.
    PressEnter,
}

/// What the page says about the element. Collected by fixed code in the page; every field is
/// untrusted text, which is why classification only ever matches it against a fixed lexicon.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Features {
    /// The ARIA role, explicit or implied by the tag; lower case.
    pub role: String,
    /// The accessible name (or a close approximation of it).
    pub name: String,
    /// The tag name, lower case.
    pub tag: String,
    /// The `type` of an input or button, lower case.
    pub input_type: String,
    /// The `autocomplete` attribute, lower case.
    pub autocomplete: String,
    /// The target of a link, resolved to an absolute URL.
    pub href: Option<String>,
    /// The action of the enclosing form, absolute.
    pub form_action: Option<String>,
    /// The method of the enclosing form, lower case (`get`, `post`, `dialog`).
    pub form_method: Option<String>,
    /// The `enctype` of the enclosing form.
    pub form_enctype: Option<String>,
    /// The `formaction` of the element itself, absolute; for an element that is not a button, the
    /// one of its form's default button, which Enter in the element presses.
    pub formaction: Option<String>,
    /// The `formmethod` of the element itself, lower case; for an element that is not a button,
    /// the one of its form's default button.
    pub formmethod: Option<String>,
    /// Whether the element is inside a form.
    pub in_form: bool,
    /// Whether the enclosing form has a password input.
    pub form_has_password: bool,
    /// Whether the enclosing form has a file input.
    pub form_has_file_input: bool,
    /// Whether the element has a `download` attribute.
    pub download: bool,
    /// Whether the element opens its target in a new tab.
    pub target_blank: bool,
    /// The `aria-expanded` state, when present.
    pub aria_expanded: Option<bool>,
    /// Whether the element has `aria-controls`.
    pub aria_controls: bool,
    /// Whether the element has `aria-haspopup`.
    pub aria_haspopup: bool,
    /// The element's DOM `id` and `name` attributes, space separated.
    pub element_id_or_name: String,
    /// The URL of the page the element is on.
    pub page_url: String,
    /// Whether the element is editable text.
    pub contenteditable: bool,
    /// Whether the element is disabled (informational; see the module docs).
    pub disabled: bool,
}

/// The class of an action and the rules that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// The strictest class any evidence points at.
    pub class: ActionClass,
    /// The ids of the rules that fired, in the order they fired, without repeats. Structural
    /// rules start with `structural.`, lexicon hits with `lexicon.`.
    pub rules: Vec<String>,
}

// ---------------------------------------------------------------------------------------------
// Lexicon

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lex {
    Destructive,
    Payment,
    Communication,
    Credential,
}

impl Lex {
    const fn class(self) -> ActionClass {
        match self {
            Self::Destructive => ActionClass::Destructive,
            Self::Payment => ActionClass::Payment,
            Self::Communication => ActionClass::ExternalCommunication,
            Self::Credential => ActionClass::CredentialEntry,
        }
    }
}

/// One row: the class, the language tag shown in rule ids, and the words. Words are written
/// naturally (with accents); a trailing `*` makes the last word a prefix.
type Row = (Lex, &'static str, &'static [&'static str]);

/// Verbs of buttons, menu items and URL paths. Logout and sign-out end the session and are
/// destructive. Small on purpose; extend by adding words or rows.
static LEXICON: &[Row] = &[
    (
        Lex::Destructive,
        "en",
        &[
            "delete",
            "remove",
            "erase",
            "destroy",
            "drop",
            "purge",
            "wipe",
            "terminate",
            "deactivate*",
            "revoke*",
            "unsubscribe",
            "close account",
            "cancel subscription",
            "cancel membership",
            "logout",
            "log out",
            "logoff",
            "log off",
            "signout",
            "sign out",
        ],
    ),
    (
        Lex::Destructive,
        "fr",
        &[
            "supprimer",
            "suppression",
            "effacer",
            "retirer",
            "désactiver",
            "résilier",
            "annuler l'abonnement",
            "déconnexion",
            "déconnecter",
        ],
    ),
    (
        Lex::Destructive,
        "de",
        &[
            "löschen",
            "entfernen",
            "deaktivieren",
            "kündigen",
            "abmelden",
            "ausloggen",
        ],
    ),
    (
        Lex::Destructive,
        "es",
        &[
            "eliminar",
            "borrar",
            "desactivar",
            "cancelar suscripción",
            "cerrar sesión",
        ],
    ),
    (
        Lex::Destructive,
        "it",
        &["eliminare", "cancella", "rimuovi", "disconnetti"],
    ),
    (Lex::Destructive, "pt", &["excluir", "remover", "apagar"]),
    (Lex::Destructive, "nl", &["verwijderen", "uitloggen"]),
    (
        Lex::Destructive,
        "tr",
        &["sil", "kaldır*", "çıkış yap", "hesabı kapat"],
    ),
    (
        Lex::Destructive,
        "zh",
        &["删除", "刪除", "退出登录", "注销"],
    ),
    (Lex::Destructive, "ja", &["削除", "ログアウト", "退会"]),
    (Lex::Destructive, "ko", &["삭제", "로그아웃"]),
    (Lex::Destructive, "ru", &["удалить*", "выйти"]),
    (
        Lex::Payment,
        "en",
        &[
            "pay",
            "payment*",
            "buy",
            "purchase*",
            "checkout",
            "place order",
            "confirm order",
            "subscribe",
            "donate*",
        ],
    ),
    (
        Lex::Payment,
        "fr",
        &["payer", "paiement", "acheter", "commander"],
    ),
    (Lex::Payment, "de", &["kaufen", "bezahlen", "bestellen"]),
    (Lex::Payment, "es", &["comprar", "pagar"]),
    (
        Lex::Payment,
        "it",
        &["acquista", "acquistare", "compra", "paga"],
    ),
    (Lex::Payment, "pt", &["comprar", "pagar"]),
    (Lex::Payment, "tr", &["satın al*", "öde"]),
    (Lex::Payment, "zh", &["购买", "購買", "支付", "付款"]),
    (Lex::Payment, "ja", &["購入", "支払"]),
    (Lex::Payment, "ko", &["구매", "결제"]),
    (Lex::Payment, "ru", &["купить", "оплатить"]),
    (
        Lex::Communication,
        "en",
        &[
            "send", "post", "posts", "publish", "share", "invite", "email", "tweet", "comment",
            "reply", "forward",
        ],
    ),
    (
        Lex::Communication,
        "fr",
        &[
            "envoyer",
            "publier",
            "partager",
            "inviter",
            "répondre",
            "commenter",
        ],
    ),
    (
        Lex::Communication,
        "de",
        &[
            "senden",
            "absenden",
            "veröffentlichen",
            "teilen",
            "einladen",
            "antworten",
        ],
    ),
    (
        Lex::Communication,
        "es",
        &["enviar", "publicar", "compartir", "invitar", "responder"],
    ),
    (
        Lex::Communication,
        "it",
        &["invia", "pubblica", "condividi", "invita"],
    ),
    (
        Lex::Communication,
        "pt",
        &["enviar", "publicar", "compartilhar"],
    ),
    (
        Lex::Communication,
        "tr",
        &["gönder*", "paylaş*", "yayınla*"],
    ),
    (Lex::Communication, "zh", &["发送", "發送", "发布", "分享"]),
    (Lex::Communication, "ja", &["送信", "投稿", "共有"]),
    (Lex::Communication, "ko", &["전송"]),
    (Lex::Communication, "ru", &["отправить", "опубликовать"]),
    (
        Lex::Credential,
        "en",
        &[
            "sign in",
            "log in",
            "login",
            "signin",
            "logon",
            "log on",
            "authenticate",
        ],
    ),
    (
        Lex::Credential,
        "fr",
        &["connexion", "se connecter", "s'identifier"],
    ),
    (Lex::Credential, "de", &["anmelden", "einloggen"]),
    (Lex::Credential, "es", &["iniciar sesión", "acceder"]),
    (Lex::Credential, "it", &["accedi", "accedere"]),
    (Lex::Credential, "pt", &["entrar"]),
    (Lex::Credential, "nl", &["inloggen"]),
    (Lex::Credential, "tr", &["giriş", "giriş yap"]),
    (Lex::Credential, "zh", &["登录", "登入"]),
    (Lex::Credential, "ja", &["ログイン"]),
    (Lex::Credential, "ko", &["로그인"]),
    (Lex::Credential, "ru", &["войти"]),
];

/// Words that mark a text field as holding a secret or a card number.
static FIELD_LEXICON: &[Row] = &[
    (
        Lex::Credential,
        "en",
        &["password", "passwd", "pwd", "passcode", "otp", "totp"],
    ),
    (Lex::Credential, "fr", &["mot de passe"]),
    (Lex::Credential, "de", &["passwort", "kennwort"]),
    (Lex::Credential, "es", &["contraseña"]),
    (Lex::Credential, "it", &["parola"]),
    (Lex::Credential, "tr", &["şifre", "parola"]),
    (Lex::Credential, "zh", &["密码", "密碼"]),
    (Lex::Credential, "ja", &["パスワード"]),
    (Lex::Credential, "ko", &["비밀번호"]),
    (Lex::Credential, "ru", &["пароль"]),
    (
        Lex::Payment,
        "en",
        &[
            "card number",
            "cardnumber",
            "ccnum",
            "cvv",
            "cvc",
            "csc",
            "iban",
        ],
    ),
    (Lex::Payment, "fr", &["numéro de carte"]),
    (Lex::Payment, "de", &["kartennummer"]),
    (Lex::Payment, "es", &["número de tarjeta"]),
];

struct Word {
    text: String,
    prefix: bool,
}

struct Term {
    class: Lex,
    lang: &'static str,
    /// Word sequence for scripts that separate words.
    words: Vec<Word>,
    /// Folded text for scripts that do not.
    substring: Option<String>,
}

fn is_cjk(c: char) -> bool {
    matches!(c,
        '\u{3040}'..='\u{30ff}' | '\u{3400}'..='\u{4dbf}' | '\u{4e00}'..='\u{9fff}'
        | '\u{ac00}'..='\u{d7af}' | '\u{ff66}'..='\u{ff9f}')
}

fn is_combining(c: char) -> bool {
    matches!(c, '\u{300}'..='\u{36f}')
}

/// Appends `c` lower-cased with common accents removed.
fn push_folded(c: char, out: &mut String) {
    for l in c.to_lowercase() {
        match l {
            'à' | 'á' | 'â' | 'ä' | 'ã' | 'å' | 'ā' => out.push('a'),
            'ç' | 'ć' | 'č' => out.push('c'),
            'è' | 'é' | 'ê' | 'ë' | 'ē' => out.push('e'),
            'ì' | 'í' | 'î' | 'ï' | 'ı' => out.push('i'),
            'ğ' => out.push('g'),
            'ñ' => out.push('n'),
            'ò' | 'ó' | 'ô' | 'ö' | 'õ' | 'ø' => out.push('o'),
            'ş' | 'š' => out.push('s'),
            'ù' | 'ú' | 'û' | 'ü' => out.push('u'),
            'ý' | 'ÿ' => out.push('y'),
            'ß' => out.push_str("ss"),
            other if is_combining(other) => {}
            other => out.push(other),
        }
    }
}

/// The whole text, folded.
fn fold(text: &str, limit: usize) -> String {
    let mut out = String::new();
    for c in text.chars().take(limit) {
        push_folded(c, &mut out);
    }
    out
}

/// The words of `text`: split on anything that is not a letter or digit and on lower-to-upper
/// case changes (`deleteAccount`), folded.
fn tokens(text: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for c in text.chars().take(limit) {
        if is_combining(c) {
            continue;
        }
        if c.is_alphanumeric() {
            if prev_lower && c.is_uppercase() && !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            push_folded(c, &mut current);
            prev_lower = c.is_lowercase();
        } else {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            prev_lower = false;
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn compile(table: &'static [Row]) -> Vec<Term> {
    let mut terms = Vec::new();
    for (class, lang, entries) in table {
        for entry in *entries {
            let (entry, prefix) = entry
                .strip_suffix('*')
                .map_or((*entry, false), |e| (e, true));
            if entry.chars().any(is_cjk) {
                terms.push(Term {
                    class: *class,
                    lang,
                    words: Vec::new(),
                    substring: Some(fold(entry, MAX_TEXT_CHARS)),
                });
                continue;
            }
            let mut words: Vec<Word> = tokens(entry, MAX_TEXT_CHARS)
                .into_iter()
                .map(|text| Word {
                    text,
                    prefix: false,
                })
                .collect();
            if let Some(last) = words.last_mut() {
                last.prefix = prefix;
                terms.push(Term {
                    class: *class,
                    lang,
                    words,
                    substring: None,
                });
            }
        }
    }
    terms
}

static COMPILED_LEXICON: LazyLock<Vec<Term>> = LazyLock::new(|| compile(LEXICON));
static COMPILED_FIELDS: LazyLock<Vec<Term>> = LazyLock::new(|| compile(FIELD_LEXICON));

fn lexicon() -> &'static [Term] {
    &COMPILED_LEXICON
}

fn field_lexicon() -> &'static [Term] {
    &COMPILED_FIELDS
}

fn phrase_matches(tokens: &[String], words: &[Word]) -> bool {
    tokens.windows(words.len()).any(|window| {
        window.iter().zip(words).all(|(token, word)| {
            if word.prefix {
                token.starts_with(&word.text)
            } else {
                *token == word.text
            }
        })
    })
}

/// A lexicon hit: the class it points at and the language of the matching row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Hit {
    class: ActionClass,
    lang: &'static str,
}

/// Every (class, language) the texts hit in `terms`, in table order.
fn scan(terms: &[Term], texts: &[&str]) -> Vec<Hit> {
    let mut hits: Vec<Hit> = Vec::new();
    for text in texts {
        let folded = fold(text, MAX_TEXT_CHARS);
        let words = tokens(text, MAX_TEXT_CHARS);
        for term in terms {
            let matched = match &term.substring {
                Some(needle) => !needle.is_empty() && folded.contains(needle.as_str()),
                None => !term.words.is_empty() && phrase_matches(&words, &term.words),
            };
            let hit = Hit {
                class: term.class.class(),
                lang: term.lang,
            };
            if matched && !hits.contains(&hit) {
                hits.push(hit);
            }
        }
    }
    hits
}

/// The path of an absolute URL.
fn path_of(url: &str) -> Option<String> {
    let capped: String = url.chars().take(MAX_URL_CHARS).collect();
    url::Url::parse(&capped).ok().map(|u| u.path().to_owned())
}

// ---------------------------------------------------------------------------------------------
// Evidence

#[derive(Default)]
struct Evidence {
    items: Vec<(ActionClass, String)>,
}

impl Evidence {
    fn add(&mut self, class: ActionClass, rule: impl Into<String>) {
        let rule = rule.into();
        if !self.items.iter().any(|(_, existing)| *existing == rule) {
            self.items.push((class, rule));
        }
    }

    fn finish(self) -> Classification {
        let class = self
            .items
            .iter()
            .map(|(class, _)| *class)
            .max_by_key(|class| class.severity())
            .unwrap_or(ActionClass::Unknown);
        let mut rules: Vec<String> = self.items.into_iter().map(|(_, rule)| rule).collect();
        if rules.is_empty() {
            rules.push("structural.no_evidence".into());
        }
        Classification { class, rules }
    }
}

// ---------------------------------------------------------------------------------------------
// Classification

const FILE_EXTENSIONS: &[&str] = &[
    "zip", "gz", "tgz", "tar", "7z", "rar", "exe", "msi", "dmg", "iso", "apk", "pkg", "deb", "rpm",
    "bin", "jar",
];

const STATIC_ROLES: &[&str] = &[
    "heading",
    "paragraph",
    "text",
    "statictext",
    "img",
    "image",
    "separator",
    "figure",
    "caption",
];

const TEXT_INPUT_TYPES: &[&str] = &[
    "",
    "text",
    "search",
    "email",
    "url",
    "tel",
    "number",
    "password",
    "date",
    "datetime-local",
    "month",
    "week",
    "time",
];

struct Probe<'a> {
    f: &'a Features,
    rw: &'a dyn Fn(&str) -> bool,
    tag: String,
    role: String,
    kind: String,
    autocomplete: Vec<String>,
    ev: Evidence,
}

/// What the model is about to do to the element, and the strictest class that implies.
///
/// `is_rw_url` says whether a URL's origin is inside the actuation scope; the caller supplies
/// the scope check.
#[must_use]
pub fn classify(
    features: &Features,
    intent: Intent,
    is_rw_url: &dyn Fn(&str) -> bool,
) -> Classification {
    let mut probe = Probe::new(features, is_rw_url);
    probe.run(intent);
    probe.ev.finish()
}

impl<'a> Probe<'a> {
    fn new(f: &'a Features, rw: &'a dyn Fn(&str) -> bool) -> Self {
        let lower = |s: &str| s.trim().to_ascii_lowercase();
        Self {
            f,
            rw,
            tag: lower(&f.tag),
            role: lower(&f.role),
            kind: lower(&f.input_type),
            autocomplete: f
                .autocomplete
                .split_whitespace()
                .map(str::to_ascii_lowercase)
                .collect(),
            ev: Evidence::default(),
        }
    }

    fn run(&mut self, intent: Intent) {
        if matches!(self.tag.as_str(), "iframe" | "frame" | "embed" | "object") {
            self.ev
                .add(ActionClass::Unknown, "structural.embedded_frame");
            return;
        }
        match intent {
            Intent::Click => self.click(),
            Intent::TypeText { submit } => self.type_text(submit),
            Intent::SelectOption => {
                self.field_evidence();
                self.ev
                    .add(ActionClass::FormEdit, "structural.select_option");
            }
            Intent::PressEnter => self.press_enter(),
        }
    }

    // --- element kinds ---------------------------------------------------------------------

    fn is_input(&self) -> bool {
        self.tag == "input"
    }

    fn is_file_input(&self) -> bool {
        self.is_input() && self.kind == "file"
    }

    fn is_text_entry(&self) -> bool {
        self.f.contenteditable
            || self.tag == "textarea"
            || (self.is_input() && TEXT_INPUT_TYPES.contains(&self.kind.as_str()))
            || matches!(self.role.as_str(), "textbox" | "searchbox" | "spinbutton")
    }

    /// Text fields that a login form collects (not free-text areas).
    fn is_line_field(&self) -> bool {
        self.is_text_entry() && !self.f.contenteditable && self.tag != "textarea"
    }

    fn is_choice(&self) -> bool {
        (self.is_input()
            && matches!(
                self.kind.as_str(),
                "checkbox" | "radio" | "range" | "color" | "reset"
            ))
            || matches!(self.tag.as_str(), "select" | "option")
            || matches!(
                self.role.as_str(),
                "checkbox"
                    | "radio"
                    | "switch"
                    | "option"
                    | "combobox"
                    | "listbox"
                    | "slider"
                    | "menuitemcheckbox"
                    | "menuitemradio"
            )
    }

    fn is_submit_capable(&self) -> bool {
        (self.tag == "button" && matches!(self.kind.as_str(), "" | "submit"))
            || (self.is_input() && matches!(self.kind.as_str(), "submit" | "image"))
    }

    fn is_button_like(&self) -> bool {
        self.tag == "button"
            || (self.is_input()
                && matches!(self.kind.as_str(), "submit" | "button" | "reset" | "image"))
            || matches!(self.role.as_str(), "button" | "menuitem")
    }

    // --- evidence helpers ------------------------------------------------------------------

    fn label_hits(&self) -> Vec<Hit> {
        scan(lexicon(), &[&self.f.name, &self.f.element_id_or_name])
    }

    /// Adds what the label says. Returns whether the label said anything.
    fn label_evidence(&mut self) -> bool {
        let hits = self.label_hits();
        for hit in &hits {
            self.ev.add(
                hit.class,
                format!("lexicon.{}.{}", hit.class.name(), hit.lang),
            );
        }
        !hits.is_empty()
    }

    /// Hits of the URL path, limited to `only` when given.
    fn path_hits(url: &str, only: Option<ActionClass>) -> Vec<Hit> {
        let Some(path) = path_of(url) else {
            return Vec::new();
        };
        scan(lexicon(), &[&path])
            .into_iter()
            .filter(|hit| only.is_none_or(|class| hit.class == class))
            .collect()
    }

    fn add_path_hit(&mut self, structural: &str, hit: Hit) {
        self.ev.add(hit.class, structural);
        self.ev.add(
            hit.class,
            format!("lexicon.path.{}.{}", hit.class.name(), hit.lang),
        );
    }

    /// Evidence about the field itself: secrets and card data.
    fn field_evidence(&mut self) {
        if self.is_input() && self.kind == "password" {
            self.ev
                .add(ActionClass::CredentialEntry, "structural.password_field");
        }
        for token in &self.autocomplete {
            if token.starts_with("cc-") {
                self.ev
                    .add(ActionClass::Payment, "structural.autocomplete_card");
            } else if matches!(
                token.as_str(),
                "current-password" | "new-password" | "one-time-code"
            ) {
                self.ev.add(
                    ActionClass::CredentialEntry,
                    "structural.autocomplete_secret",
                );
            }
        }
        if self.is_line_field() && self.f.in_form && self.f.form_has_password {
            self.ev.add(
                ActionClass::CredentialEntry,
                "structural.field_in_credential_form",
            );
        }
        if self.is_text_entry() {
            let hits = scan(field_lexicon(), &[&self.f.name, &self.f.element_id_or_name]);
            for hit in hits {
                self.ev.add(
                    hit.class,
                    format!("lexicon.field.{}.{}", hit.class.name(), hit.lang),
                );
            }
        }
    }

    // --- intents ---------------------------------------------------------------------------

    fn click(&mut self) {
        if self.is_file_input() {
            self.ev
                .add(ActionClass::FileTransfer, "structural.file_input");
            return;
        }
        if self.f.href.is_some() {
            self.link();
            return;
        }
        self.field_evidence();
        if self.is_submit_capable() && self.f.in_form {
            self.submit(true);
            return;
        }
        if self.is_text_entry() {
            self.ev.add(ActionClass::FormEdit, "structural.field_focus");
            return;
        }
        if self.is_choice() {
            self.ev.add(ActionClass::FormEdit, "structural.field_edit");
            return;
        }
        if matches!(self.role.as_str(), "tab" | "treeitem") {
            self.ev.add(ActionClass::Read, "structural.tab");
            return;
        }
        let disclosure = self.tag == "summary"
            || (self.is_button_like()
                && (self.f.aria_expanded.is_some()
                    || self.f.aria_controls
                    || self.f.aria_haspopup));
        if disclosure {
            self.ev.add(ActionClass::Read, "structural.disclosure");
            self.label_evidence();
            return;
        }
        if STATIC_ROLES.contains(&self.role.as_str()) {
            self.ev.add(ActionClass::Read, "structural.static_content");
            return;
        }
        if !self.label_evidence() {
            self.ev
                .add(ActionClass::Unknown, "structural.unclassified_actuator");
        }
    }

    fn link(&mut self) {
        let Some(href) = self.f.href.as_deref() else {
            return;
        };
        let lower = href.trim_start().to_ascii_lowercase();
        if ["mailto:", "tel:", "sms:"]
            .iter()
            .any(|scheme| lower.starts_with(scheme))
        {
            self.ev.add(
                ActionClass::ExternalCommunication,
                "structural.link_message_scheme",
            );
            return;
        }
        if lower.starts_with("javascript:") {
            self.ev
                .add(ActionClass::Unknown, "structural.link_javascript");
            self.label_evidence();
            return;
        }
        if self.same_document(href) {
            self.ev.add(
                ActionClass::NavigateInScope,
                "structural.link_same_document",
            );
            self.label_evidence();
        } else if (self.rw)(href) {
            self.ev
                .add(ActionClass::NavigateInScope, "structural.link_in_scope");
        } else {
            self.ev.add(
                ActionClass::NavigateOutOfScope,
                "structural.link_out_of_scope",
            );
        }
        for hit in Self::path_hits(href, Some(ActionClass::Destructive)) {
            self.add_path_hit("structural.link_destructive_path", hit);
        }
        if self.f.download {
            self.ev
                .add(ActionClass::FileTransfer, "structural.link_download");
        }
        let has_file_extension = path_of(href)
            .and_then(|path| {
                path.rsplit('/')
                    .next()
                    .and_then(|file| file.rsplit_once('.'))
                    .map(|(_, ext)| ext.to_ascii_lowercase())
            })
            .is_some_and(|ext| FILE_EXTENSIONS.contains(&ext.as_str()));
        if has_file_extension {
            self.ev
                .add(ActionClass::FileTransfer, "structural.link_file_extension");
        }
    }

    /// Whether the link only points into the page it is on.
    fn same_document(&self, href: &str) -> bool {
        let base = |url: &str| url.split('#').next().unwrap_or("").to_owned();
        !self.f.page_url.is_empty() && base(href) == base(&self.f.page_url)
    }

    fn submit(&mut self, via_button: bool) {
        let method = self
            .f
            .formmethod
            .as_deref()
            .or(self.f.form_method.as_deref())
            .map_or_else(|| "get".to_owned(), |m| m.trim().to_ascii_lowercase());
        let action = self
            .f
            .formaction
            .as_deref()
            .or(self.f.form_action.as_deref())
            .or(Some(self.f.page_url.as_str()).filter(|url| !url.is_empty()));
        match method.as_str() {
            "dialog" => self.ev.add(ActionClass::Read, "structural.form_dialog"),
            "get" => {
                match action {
                    Some(url) if (self.rw)(url) => self.ev.add(
                        ActionClass::NavigateInScope,
                        "structural.submit_get_in_scope",
                    ),
                    Some(_) => self.ev.add(
                        ActionClass::NavigateOutOfScope,
                        "structural.submit_get_out_of_scope",
                    ),
                    None => self
                        .ev
                        .add(ActionClass::Unknown, "structural.form_action_unknown"),
                }
                if let Some(url) = action {
                    for hit in Self::path_hits(url, Some(ActionClass::Destructive)) {
                        self.add_path_hit("structural.form_get_destructive_path", hit);
                    }
                }
                if self.f.form_has_password {
                    self.ev
                        .add(ActionClass::CredentialEntry, "structural.form_has_password");
                }
                if via_button && self.f.formaction.is_some() {
                    self.label_evidence();
                }
            }
            _ => {
                self.ev.add(
                    ActionClass::SubmitStateChange,
                    "structural.submit_state_change",
                );
                match action {
                    Some(url) => {
                        if !(self.rw)(url) {
                            self.ev.add(
                                ActionClass::ExternalCommunication,
                                "structural.form_post_out_of_scope",
                            );
                        }
                        for hit in Self::path_hits(url, None) {
                            let structural = match hit.class {
                                ActionClass::Destructive => "structural.form_post_destructive_path",
                                ActionClass::Payment => "structural.form_post_payment_path",
                                ActionClass::ExternalCommunication => {
                                    "structural.form_post_communication_path"
                                }
                                _ => "structural.form_post_login_path",
                            };
                            self.add_path_hit(structural, hit);
                        }
                    }
                    None => self
                        .ev
                        .add(ActionClass::Unknown, "structural.form_action_unknown"),
                }
                if self.f.form_has_password {
                    self.ev
                        .add(ActionClass::CredentialEntry, "structural.form_has_password");
                }
                if self.f.form_has_file_input {
                    self.ev
                        .add(ActionClass::FileTransfer, "structural.form_has_file_input");
                }
                if via_button {
                    self.label_evidence();
                }
            }
        }
    }

    fn type_text(&mut self, submit: bool) {
        self.field_evidence();
        if self.is_file_input() {
            self.ev
                .add(ActionClass::FileTransfer, "structural.file_input");
            return;
        }
        let multiline = self.f.contenteditable || self.tag == "textarea";
        if submit && self.f.in_form && !multiline {
            self.submit(false);
            return;
        }
        if self.is_text_entry() {
            self.ev.add(ActionClass::FormEdit, "structural.text_entry");
        } else {
            self.ev
                .add(ActionClass::Unknown, "structural.type_into_non_field");
        }
        if submit {
            self.ev
                .add(ActionClass::Unknown, "structural.enter_without_form");
        }
    }

    fn press_enter(&mut self) {
        if self.f.href.is_some() || self.is_button_like() {
            self.click();
            return;
        }
        self.field_evidence();
        if self.f.contenteditable || self.tag == "textarea" {
            self.ev.add(ActionClass::FormEdit, "structural.text_entry");
            if !self.f.in_form {
                self.ev
                    .add(ActionClass::Unknown, "structural.enter_without_form");
            }
        } else if self.f.in_form {
            self.submit(false);
        } else if self.is_text_entry() {
            self.ev
                .add(ActionClass::Unknown, "structural.enter_without_form");
        } else {
            self.ev.add(ActionClass::Read, "structural.enter_no_effect");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::collections::BTreeSet;

    use super::*;

    fn rw(url: &str) -> bool {
        url == "https://app.example.test" || url.starts_with("https://app.example.test/")
    }

    fn base() -> Features {
        Features {
            page_url: "https://app.example.test/settings".into(),
            ..Features::default()
        }
    }

    fn button(name: &str) -> Features {
        Features {
            role: "button".into(),
            tag: "button".into(),
            input_type: "button".into(),
            name: name.into(),
            ..base()
        }
    }

    fn post_form_button(name: &str, action: &str) -> Features {
        Features {
            input_type: "submit".into(),
            in_form: true,
            form_method: Some("post".into()),
            form_action: Some(action.into()),
            ..button(name)
        }
    }

    fn link(name: &str, href: &str) -> Features {
        Features {
            role: "link".into(),
            tag: "a".into(),
            name: name.into(),
            href: Some(href.into()),
            ..base()
        }
    }

    fn class_of(f: &Features, intent: Intent) -> ActionClass {
        classify(f, intent, &rw).class
    }

    #[test]
    fn decision_table_matches_the_documented_rows() {
        use ActionClass as C;
        use Decision as D;
        for class in C::ALL {
            let read_only = match class {
                C::Read | C::NavigateInScope => D::Allow,
                _ => D::Deny,
            };
            assert_eq!(decide(Profile::ReadOnly, class), read_only, "{class:?}");
            let test = match class {
                C::Read | C::NavigateInScope | C::FormEdit | C::SubmitStateChange => D::Allow,
                C::NavigateOutOfScope | C::Payment => D::Deny,
                _ => D::Approval,
            };
            assert_eq!(decide(Profile::TestEnvironment, class), test, "{class:?}");
            let security = if class == C::Unknown { D::Allow } else { test };
            assert_eq!(
                decide(Profile::AuthorizedSecurityTest, class),
                security,
                "{class:?}"
            );
        }
        assert_eq!(table().len(), 33);
    }

    #[test]
    fn severity_is_a_strict_total_order_and_decisions_never_relax_with_it() {
        let mut by_severity = ActionClass::ALL.to_vec();
        by_severity.sort_by_key(|c| c.severity());
        let severities: Vec<u8> = by_severity.iter().map(|c| c.severity()).collect();
        let mut unique = severities.clone();
        unique.dedup();
        assert_eq!(severities, unique, "severities must be distinct");
        assert_eq!(by_severity.first(), Some(&ActionClass::Read));
        assert!(ActionClass::Unknown.severity() > ActionClass::SubmitStateChange.severity());
        assert!(
            ActionClass::Destructive.severity() > ActionClass::Unknown.severity()
                && ActionClass::Payment.severity() > ActionClass::Destructive.severity()
        );
        for profile in Profile::ALL {
            let decisions: Vec<Decision> =
                by_severity.iter().map(|c| decide(profile, *c)).collect();
            assert!(decisions.is_sorted(), "{profile:?}: {decisions:?}");
        }
    }

    #[test]
    fn class_names_round_trip_and_match_serde() {
        for class in ActionClass::ALL {
            assert_eq!(ActionClass::parse(class.name()), Some(class));
            assert_eq!(
                serde_json::to_value(class).unwrap(),
                serde_json::json!(class.name())
            );
        }
        assert_eq!(ActionClass::parse("nope"), None);
        assert_eq!(stricter(Decision::Allow, Decision::Deny), Decision::Deny);
        assert_eq!(
            stricter(Decision::Approval, Decision::Allow),
            Decision::Approval
        );
    }

    #[test]
    fn intents_serialize_with_a_kind_tag() {
        assert_eq!(
            serde_json::to_value(Intent::TypeText { submit: true }).unwrap(),
            serde_json::json!({"kind": "type_text", "submit": true})
        );
        let intent: Intent = serde_json::from_value(serde_json::json!({"kind": "click"})).unwrap();
        assert_eq!(intent, Intent::Click);
    }

    #[test]
    fn folding_and_tokens_handle_accents_case_and_camel_case() {
        assert_eq!(fold("Désactiver Çıkış İŞ", 64), "desactiver cikis is");
        assert_eq!(
            tokens("deleteAccount-now_ok", 64),
            ["delete", "account", "now", "ok"]
        );
        assert_eq!(tokens("l'abonnement", 64), ["l", "abonnement"]);
        // Decomposed accents fold like precomposed ones.
        assert_eq!(tokens("de\u{301}sactiver", 64), ["desactiver"]);
    }

    #[test]
    fn destructive_labels_in_a_post_form_are_destructive_in_every_listed_language() {
        for name in [
            "Delete account",
            "Supprimer le compte",
            "Konto löschen",
            "Eliminar cuenta",
            "Hesabı sil",
            "Cancelar suscripción",
            "Annuler l'abonnement",
            "删除账户",
            "アカウントを削除",
            "계정 삭제",
            "Удалить аккаунт",
            "Se déconnecter",
            "Abmelden",
            "Cerrar sesión",
            "Remove item",
            "Rimuovi",
            "Excluir conta",
            "Verwijderen",
            "Close account",
        ] {
            let f = post_form_button(name, "https://app.example.test/settings");
            let c = classify(&f, Intent::Click, &rw);
            assert_eq!(c.class, ActionClass::Destructive, "{name}: {c:?}");
            assert!(
                c.rules
                    .iter()
                    .any(|r| r.starts_with("lexicon.destructive.")),
                "{name}: {c:?}"
            );
        }
    }

    #[test]
    fn a_benign_label_cannot_hide_a_destructive_post() {
        let f = post_form_button("Cancel", "https://app.example.test/account/delete");
        let c = classify(&f, Intent::Click, &rw);
        assert_eq!(c.class, ActionClass::Destructive);
        assert!(
            c.rules
                .contains(&"structural.form_post_destructive_path".to_owned()),
            "{c:?}"
        );
        let f = post_form_button("Save", "https://app.example.test/settings");
        assert_eq!(class_of(&f, Intent::Click), ActionClass::SubmitStateChange);
    }

    #[test]
    fn formaction_override_is_structural_evidence() {
        let mut f = post_form_button("Save", "https://app.example.test/settings");
        f.formaction = Some("https://app.example.test/delete".into());
        assert_eq!(class_of(&f, Intent::Click), ActionClass::Destructive);
        // A GET form whose button carries a formaction makes the label count.
        let mut f = post_form_button("Delete", "https://app.example.test/search");
        f.form_method = Some("get".into());
        assert_eq!(class_of(&f, Intent::Click), ActionClass::NavigateInScope);
        f.formaction = Some("https://app.example.test/x".into());
        assert_eq!(class_of(&f, Intent::Click), ActionClass::Destructive);
    }

    #[test]
    fn links_split_by_scope_scheme_and_path() {
        assert_eq!(
            class_of(
                &link("Docs", "https://app.example.test/docs"),
                Intent::Click
            ),
            ActionClass::NavigateInScope
        );
        assert_eq!(
            class_of(&link("Docs", "https://other.example.net/"), Intent::Click),
            ActionClass::NavigateOutOfScope
        );
        assert_eq!(
            class_of(&link("Mail", "mailto:team@example.test"), Intent::Click),
            ActionClass::ExternalCommunication
        );
        assert_eq!(
            class_of(&link("Call", "TEL:+15550100"), Intent::Click),
            ActionClass::ExternalCommunication
        );
        assert_eq!(
            class_of(&link("Go", "javascript:void(0)"), Intent::Click),
            ActionClass::Unknown
        );
        // The label does not make an in-scope read link destructive; the path does.
        assert_eq!(
            class_of(
                &link("Delete", "https://app.example.test/help"),
                Intent::Click
            ),
            ActionClass::NavigateInScope
        );
        for path in ["/logout", "/account/delete", "/items/remove", "/sign-out"] {
            let f = link("Go", &format!("https://app.example.test{path}"));
            assert_eq!(
                class_of(&f, Intent::Click),
                ActionClass::Destructive,
                "{path}"
            );
        }
        let mut f = link("Report", "https://app.example.test/report.csv");
        f.download = true;
        assert_eq!(class_of(&f, Intent::Click), ActionClass::FileTransfer);
        let f = link("Get", "https://app.example.test/tool.zip");
        assert_eq!(class_of(&f, Intent::Click), ActionClass::FileTransfer);
        // Out of scope wins over file transfer: it is the stricter decision.
        let mut f = link("Get", "https://other.example.net/a.zip");
        f.download = true;
        assert_eq!(class_of(&f, Intent::Click), ActionClass::NavigateOutOfScope);
    }

    #[test]
    fn fragment_links_are_read_as_actuators() {
        let f = link("Skip to content", "https://app.example.test/settings#main");
        assert_eq!(class_of(&f, Intent::Click), ActionClass::NavigateInScope);
        let f = link("Delete", "https://app.example.test/settings#");
        assert_eq!(class_of(&f, Intent::Click), ActionClass::Destructive);
    }

    #[test]
    fn credentials_and_payment_fields() {
        let password = Features {
            tag: "input".into(),
            input_type: "password".into(),
            role: "textbox".into(),
            ..base()
        };
        assert_eq!(
            class_of(&password, Intent::TypeText { submit: false }),
            ActionClass::CredentialEntry
        );
        assert_eq!(
            class_of(&password, Intent::Click),
            ActionClass::CredentialEntry
        );
        let card = Features {
            tag: "input".into(),
            input_type: "text".into(),
            role: "textbox".into(),
            autocomplete: "section-pay cc-number".into(),
            ..base()
        };
        assert_eq!(
            class_of(&card, Intent::TypeText { submit: false }),
            ActionClass::Payment
        );
        let by_name = Features {
            tag: "input".into(),
            input_type: "text".into(),
            role: "textbox".into(),
            element_id_or_name: "cardNumber".into(),
            ..base()
        };
        assert_eq!(
            class_of(&by_name, Intent::TypeText { submit: false }),
            ActionClass::Payment
        );
        let user = Features {
            tag: "input".into(),
            input_type: "text".into(),
            role: "textbox".into(),
            autocomplete: "username".into(),
            in_form: true,
            form_has_password: true,
            ..base()
        };
        assert_eq!(
            class_of(&user, Intent::TypeText { submit: false }),
            ActionClass::CredentialEntry
        );
        let search = Features {
            tag: "input".into(),
            input_type: "search".into(),
            role: "searchbox".into(),
            ..base()
        };
        assert_eq!(
            class_of(&search, Intent::TypeText { submit: false }),
            ActionClass::FormEdit
        );
    }

    #[test]
    fn forms_submit_as_navigation_or_state_change() {
        let get_form = Features {
            tag: "input".into(),
            input_type: "search".into(),
            role: "searchbox".into(),
            in_form: true,
            form_method: Some("get".into()),
            form_action: Some("https://app.example.test/search".into()),
            ..base()
        };
        assert_eq!(
            class_of(&get_form, Intent::TypeText { submit: true }),
            ActionClass::NavigateInScope
        );
        assert_eq!(
            class_of(&get_form, Intent::PressEnter),
            ActionClass::NavigateInScope
        );
        let mut off = get_form.clone();
        off.form_action = Some("https://search.example.net/".into());
        assert_eq!(
            class_of(&off, Intent::PressEnter),
            ActionClass::NavigateOutOfScope
        );
        let mut post = get_form;
        post.form_method = Some("post".into());
        post.form_action = Some("https://app.example.test/notes".into());
        assert_eq!(
            class_of(&post, Intent::TypeText { submit: true }),
            ActionClass::SubmitStateChange
        );
        post.form_action = Some("https://collector.example.net/".into());
        assert_eq!(
            class_of(&post, Intent::TypeText { submit: true }),
            ActionClass::ExternalCommunication
        );
        post.form_action = Some("https://app.example.test/checkout".into());
        assert_eq!(class_of(&post, Intent::PressEnter), ActionClass::Payment);
        post.form_action = Some("https://app.example.test/login".into());
        assert_eq!(
            class_of(&post, Intent::PressEnter),
            ActionClass::CredentialEntry
        );
        post.form_has_file_input = true;
        post.form_action = Some("https://app.example.test/notes".into());
        assert_eq!(
            class_of(&post, Intent::PressEnter),
            ActionClass::FileTransfer
        );
    }

    #[test]
    fn plain_actuators_are_unknown_unless_the_label_says_more() {
        assert_eq!(
            class_of(&button("Continue"), Intent::Click),
            ActionClass::Unknown
        );
        assert_eq!(
            class_of(&button("Delete"), Intent::Click),
            ActionClass::Destructive
        );
        assert_eq!(
            class_of(&button("Buy now"), Intent::Click),
            ActionClass::Payment
        );
        assert_eq!(
            class_of(&button("Send"), Intent::Click),
            ActionClass::ExternalCommunication
        );
        assert_eq!(
            class_of(&button("Sign in"), Intent::Click),
            ActionClass::CredentialEntry
        );
        let c = classify(&button("Continue"), Intent::Click, &rw);
        assert_eq!(c.rules, ["structural.unclassified_actuator"]);
        // An id or name attribute is read like a label.
        let mut f = button("OK");
        f.element_id_or_name = "deleteAccountBtn".into();
        assert_eq!(class_of(&f, Intent::Click), ActionClass::Destructive);
    }

    #[test]
    fn disclosure_tabs_and_choices_are_not_state_changes() {
        let mut f = button("Menu");
        f.aria_expanded = Some(false);
        assert_eq!(class_of(&f, Intent::Click), ActionClass::Read);
        let mut f = button("More");
        f.aria_haspopup = true;
        assert_eq!(class_of(&f, Intent::Click), ActionClass::Read);
        let tab = Features {
            role: "tab".into(),
            name: "Billing".into(),
            ..base()
        };
        assert_eq!(class_of(&tab, Intent::Click), ActionClass::Read);
        let check = Features {
            role: "checkbox".into(),
            tag: "input".into(),
            input_type: "checkbox".into(),
            name: "Delete me".into(),
            ..base()
        };
        assert_eq!(class_of(&check, Intent::Click), ActionClass::FormEdit);
        let select = Features {
            role: "combobox".into(),
            tag: "select".into(),
            ..base()
        };
        assert_eq!(
            class_of(&select, Intent::SelectOption),
            ActionClass::FormEdit
        );
        // A disclosure that is also labelled with a destructive verb reads the strict way.
        let mut f = button("Delete…");
        f.aria_haspopup = true;
        assert_eq!(class_of(&f, Intent::Click), ActionClass::Destructive);
    }

    #[test]
    fn file_inputs_and_frames() {
        let file = Features {
            tag: "input".into(),
            input_type: "file".into(),
            ..base()
        };
        assert_eq!(class_of(&file, Intent::Click), ActionClass::FileTransfer);
        assert_eq!(
            class_of(&file, Intent::TypeText { submit: false }),
            ActionClass::FileTransfer
        );
        let frame = Features {
            tag: "iframe".into(),
            ..base()
        };
        assert_eq!(class_of(&frame, Intent::PressEnter), ActionClass::Unknown);
    }

    #[test]
    fn enter_without_a_form_is_a_read_unless_a_field_or_actuator_has_focus() {
        let div = Features {
            tag: "div".into(),
            ..base()
        };
        assert_eq!(class_of(&div, Intent::PressEnter), ActionClass::Read);
        let chat = Features {
            tag: "input".into(),
            input_type: "text".into(),
            role: "textbox".into(),
            ..base()
        };
        assert_eq!(class_of(&chat, Intent::PressEnter), ActionClass::Unknown);
        assert_eq!(
            class_of(&chat, Intent::TypeText { submit: true }),
            ActionClass::Unknown
        );
        assert_eq!(
            class_of(&chat, Intent::TypeText { submit: false }),
            ActionClass::FormEdit
        );
        assert_eq!(
            class_of(&button("Delete"), Intent::PressEnter),
            ActionClass::Destructive
        );
    }

    #[test]
    fn tokens_match_whole_words_not_substrings() {
        for name in [
            "Silver plan",
            "Dropdown",
            "Postal code",
            "Payload",
            "Remote",
        ] {
            let f = button(name);
            assert_eq!(class_of(&f, Intent::Click), ActionClass::Unknown, "{name}");
        }
        for name in ["Payments", "Please pay now", "Deactivated"] {
            let class = class_of(&button(name), Intent::Click);
            assert!(
                matches!(class, ActionClass::Payment | ActionClass::Destructive),
                "{name}"
            );
        }
    }

    /// Features over a grid of tags, forms and URLs.
    fn grid() -> Vec<(Features, Intent)> {
        let mut out = Vec::new();
        let tags = [
            ("button", "button", "submit"),
            ("button", "button", "button"),
            ("input", "textbox", "text"),
            ("input", "", "submit"),
            ("a", "link", ""),
            ("div", "", ""),
            ("input", "checkbox", "checkbox"),
        ];
        let intents = [
            Intent::Click,
            Intent::TypeText { submit: true },
            Intent::TypeText { submit: false },
            Intent::SelectOption,
            Intent::PressEnter,
        ];
        let actions = [
            None,
            Some("https://app.example.test/search"),
            Some("https://other.example.net/x"),
            Some("https://app.example.test/account/delete"),
        ];
        for (tag, role, kind) in tags {
            for method in [None, Some("get"), Some("post")] {
                for action in actions {
                    for in_form in [false, true] {
                        for password in [false, true] {
                            for intent in intents {
                                let f = Features {
                                    tag: tag.into(),
                                    role: role.into(),
                                    input_type: kind.into(),
                                    in_form,
                                    form_has_password: in_form && password,
                                    form_method: method.map(str::to_owned),
                                    form_action: action.map(str::to_owned),
                                    href: (tag == "a")
                                        .then(|| "https://app.example.test/page".into()),
                                    ..base()
                                };
                                out.push((f, intent));
                            }
                        }
                    }
                }
            }
        }
        out
    }

    #[test]
    fn labels_never_lower_a_class_and_benign_labels_change_nothing() {
        for (f, intent) in grid() {
            let bare = classify(&f, intent, &rw);
            for benign in ["Cancel", "Read more", "Save", "OK", "Annuler"] {
                let mut named = f.clone();
                named.name = benign.into();
                assert_eq!(
                    classify(&named, intent, &rw).class,
                    bare.class,
                    "{benign}: {f:?} {intent:?}"
                );
            }
            for loud in ["Delete", "Supprimer", "Buy", "Send", "Sign in", "Pay"] {
                let mut named = f.clone();
                named.name = loud.into();
                let with = classify(&named, intent, &rw);
                assert!(
                    with.class.severity() >= bare.class.severity(),
                    "{loud} lowered {:?} to {:?}: {f:?} {intent:?}",
                    bare.class,
                    with.class
                );
            }
        }
    }

    #[test]
    fn classification_is_deterministic_and_lists_its_rules() {
        for (f, intent) in grid().into_iter().take(500) {
            let first = classify(&f, intent, &rw);
            assert_eq!(first, classify(&f, intent, &rw));
            assert!(!first.rules.is_empty());
            let unique: BTreeSet<&String> = first.rules.iter().collect();
            assert_eq!(unique.len(), first.rules.len(), "{first:?}");
        }
    }

    #[test]
    fn hostile_input_stays_bounded() {
        let mut f = button(&"delete ".repeat(100_000));
        f.element_id_or_name = "x".repeat(1_000_000);
        f.page_url = "https://app.example.test/".repeat(10_000);
        f.href = Some(format!(
            "https://app.example.test/{}",
            "a/".repeat(1_000_000)
        ));
        let started = std::time::Instant::now();
        let _ = classify(&f, Intent::Click, &rw);
        let _ = classify(&button(&"\u{301}".repeat(1_000_000)), Intent::Click, &rw);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
