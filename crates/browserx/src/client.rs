//! Client commands against a running server.

use anyhow::{Context, Result, bail};
use reqwest::Method;
use serde_json::{Map, Value, json};

use crate::cli::{CreateArgs, Remote, SessionCommand};

struct Client {
    http: reqwest::Client,
    base: String,
    api_key: String,
    token: Option<String>,
}

impl Client {
    fn new(remote: &Remote) -> Result<Self> {
        let api_key = remote
            .api_key
            .clone()
            .filter(|k| !k.is_empty())
            .context("an API key is required: pass --api-key or set BROWSERX_API_KEY")?;
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(180))
                .build()
                .context("cannot build the HTTP client")?,
            base: remote.server.trim_end_matches('/').to_owned(),
            api_key,
            token: remote.token.clone().filter(|t| !t.is_empty()),
        })
    }

    fn token(&self) -> Result<&str> {
        self.token
            .as_deref()
            .context("a session token is required: pass --token or set BROWSERX_TOKEN")
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.api_key);
        if let Some(t) = token {
            req = req.header("X-BrowserX-Token", t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("cannot reach {}", self.base))?;
        let status = resp.status();
        let text = resp.text().await.context("cannot read the response")?;
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(value);
        }
        match (
            value.pointer("/error/code").and_then(Value::as_str),
            value.pointer("/error/message").and_then(Value::as_str),
        ) {
            (Some(code), Some(message)) => bail!("{} {code}: {message}", status.as_u16()),
            _ => bail!(
                "HTTP {}: {}",
                status.as_u16(),
                text.chars().take(300).collect::<String>()
            ),
        }
    }
}

fn create_body(a: &CreateArgs) -> Result<Value> {
    let mut spec = Map::new();
    if let Some(p) = a.persistence {
        spec.insert("persistence".into(), json!(p.api()));
    }
    if let Some(i) = a.isolation {
        spec.insert("isolation".into(), json!(i.api()));
    }
    if let Some(r) = a.recovery {
        spec.insert("recovery".into(), json!(r.api()));
    }
    for (key, value) in [
        ("profile_id", a.profile_id.as_ref()),
        ("launch_profile", a.launch_profile.as_ref()),
    ] {
        if let Some(v) = value {
            spec.insert(key.into(), json!(v));
        }
    }
    for (key, value) in [
        ("ttl_secs", a.ttl_secs),
        ("max_lifetime_secs", a.max_lifetime_secs),
        ("idle_timeout_secs", a.idle_timeout_secs),
    ] {
        if let Some(v) = value {
            spec.insert(key.into(), json!(v));
        }
    }
    if let Some(url) = &a.proxy_url {
        spec.insert(
            "proxy".into(),
            json!({ "url": url, "username": a.proxy_username, "password": a.proxy_password }),
        );
    }
    if !a.labels.is_empty() {
        let mut labels = Map::new();
        for raw in &a.labels {
            let (k, v) = raw
                .split_once('=')
                .with_context(|| format!("label `{raw}` must be KEY=VALUE"))?;
            labels.insert(k.to_owned(), json!(v));
        }
        spec.insert("labels".into(), Value::Object(labels));
    }
    Ok(Value::Object(spec))
}

/// Runs one client command and prints the JSON response.
pub async fn run(remote: &Remote, command: SessionCommand) -> Result<()> {
    let client = Client::new(remote)?;
    let value = match command {
        SessionCommand::Create(args) => {
            client
                .send(
                    Method::POST,
                    "/v1/sessions",
                    None,
                    Some(create_body(&args)?),
                )
                .await?
        }
        SessionCommand::List { status } => {
            let path = match status {
                Some(s) => format!("/v1/sessions?status={s}"),
                None => "/v1/sessions".to_owned(),
            };
            client.send(Method::GET, &path, None, None).await?
        }
        SessionCommand::Get { id } => {
            client
                .send(Method::GET, &format!("/v1/sessions/{id}"), None, None)
                .await?
        }
        SessionCommand::Attach { id } => {
            client
                .send(
                    Method::POST,
                    &format!("/v1/sessions/{id}/attach"),
                    Some(client.token()?),
                    None,
                )
                .await?
        }
        SessionCommand::Renew {
            id,
            generation,
            ttl_secs,
        } => {
            let body = json!({ "generation": generation, "ttl_secs": ttl_secs });
            client
                .send(
                    Method::POST,
                    &format!("/v1/sessions/{id}/renew"),
                    Some(client.token()?),
                    Some(body),
                )
                .await?
        }
        SessionCommand::Handoff { id, generation } => {
            let body = json!({ "generation": generation });
            client
                .send(
                    Method::POST,
                    &format!("/v1/sessions/{id}/handoff"),
                    Some(client.token()?),
                    Some(body),
                )
                .await?
        }
        SessionCommand::Snapshot { id } => {
            client
                .send(
                    Method::POST,
                    &format!("/v1/sessions/{id}/snapshot"),
                    Some(client.token()?),
                    None,
                )
                .await?
        }
        SessionCommand::Release { id, generation } => {
            let path = match generation {
                Some(g) => format!("/v1/sessions/{id}?generation={g}"),
                None => format!("/v1/sessions/{id}"),
            };
            client
                .send(Method::DELETE, &path, client.token.as_deref(), None)
                .await?
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, Command};

    #[test]
    fn create_flags_become_a_session_spec() {
        let cli = Cli::parse_from([
            "browserx",
            "session",
            "--api-key",
            "k",
            "create",
            "--persistence",
            "snapshot",
            "--isolation",
            "shared",
            "--ttl-secs",
            "90",
            "--label",
            "a=b",
            "--label",
            "c=d=e",
            "--proxy-url",
            "socks5://p.test:1080",
            "--proxy-username",
            "u-{session}",
        ]);
        let Command::Session {
            command: SessionCommand::Create(args),
            ..
        } = cli.command
        else {
            panic!("wrong command");
        };
        let body = create_body(&args).unwrap();
        assert_eq!(body["persistence"], "snapshot");
        assert_eq!(body["isolation"], "shared_browser");
        assert_eq!(body["ttl_secs"], 90);
        assert_eq!(body["labels"], json!({"a": "b", "c": "d=e"}));
        assert_eq!(body["proxy"]["username"], "u-{session}");
    }

    #[test]
    fn empty_create_is_an_empty_spec_and_bad_labels_fail() {
        let cli = Cli::parse_from(["browserx", "session", "--api-key", "k", "create"]);
        let Command::Session {
            command: SessionCommand::Create(args),
            ..
        } = cli.command
        else {
            panic!("wrong command");
        };
        assert_eq!(create_body(&args).unwrap(), json!({}));
        let cli = Cli::parse_from(["browserx", "session", "create", "--label", "nokey"]);
        let Command::Session {
            command: SessionCommand::Create(args),
            ..
        } = cli.command
        else {
            panic!("wrong command");
        };
        assert!(create_body(&args).is_err());
    }
}
