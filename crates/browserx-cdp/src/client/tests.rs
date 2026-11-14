#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::Future;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use super::*;

type ServerWs = WebSocketStream<tokio::net::TcpStream>;

/// Starts an in-process fake browser; `handler` drives one accepted connection.
async fn fake_server<F, Fut>(handler: F) -> (String, JoinHandle<()>)
where
    F: FnOnce(ServerWs) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        handler(ws).await;
    });
    (url, task)
}

async fn next_command(ws: &mut ServerWs) -> Option<Value> {
    loop {
        match ws.next().await? {
            Ok(Message::Text(text)) => return Some(serde_json::from_str(text.as_str()).unwrap()),
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => {}
        }
    }
}

async fn send_json(ws: &mut ServerWs, value: Value) {
    ws.send(Message::text(value.to_string())).await.unwrap();
}

fn quick() -> CdpLimits {
    CdpLimits {
        command_timeout: Duration::from_secs(5),
        ..CdpLimits::default()
    }
}

#[tokio::test]
async fn call_round_trip_carries_params_and_session() {
    let (url, _server) = fake_server(|mut ws| async move {
        while let Some(cmd) = next_command(&mut ws).await {
            let result = json!({
                "method": cmd["method"],
                "params": cmd["params"],
                "session": cmd.get("sessionId").cloned().unwrap_or(Value::Null),
            });
            send_json(&mut ws, json!({"id": cmd["id"], "result": result})).await;
        }
    })
    .await;
    let client = CdpClient::connect(&url, quick()).await.unwrap();
    let plain = client
        .call("Browser.getVersion", json!({"a": 1}), None)
        .await
        .unwrap();
    assert_eq!(plain["method"], "Browser.getVersion");
    assert_eq!(plain["params"]["a"], 1);
    assert_eq!(plain["session"], Value::Null);
    let scoped = client
        .call("Runtime.evaluate", json!({}), Some("SESSION-1"))
        .await
        .unwrap();
    assert_eq!(scoped["session"], "SESSION-1");
    client.close().await;
}

#[tokio::test]
async fn out_of_order_replies_reach_the_right_caller() {
    let (url, _server) = fake_server(|mut ws| async move {
        let mut commands = Vec::new();
        for _ in 0..3 {
            commands.push(next_command(&mut ws).await.unwrap());
        }
        for cmd in commands.iter().rev() {
            send_json(
                &mut ws,
                json!({"id": cmd["id"], "result": {"m": cmd["method"]}}),
            )
            .await;
        }
        let _ = ws.next().await;
    })
    .await;
    let client = CdpClient::connect(&url, quick()).await.unwrap();
    let (a, b, c) = tokio::join!(
        client.call("A.a", json!({}), None),
        client.call("B.b", json!({}), None),
        client.call("C.c", json!({}), None),
    );
    assert_eq!(a.unwrap()["m"], "A.a");
    assert_eq!(b.unwrap()["m"], "B.b");
    assert_eq!(c.unwrap()["m"], "C.c");
}

#[tokio::test]
async fn protocol_error_is_typed_and_names_the_method() {
    let (url, _server) = fake_server(|mut ws| async move {
        let cmd = next_command(&mut ws).await.unwrap();
        send_json(
            &mut ws,
            json!({"id": cmd["id"], "error": {"code": -32601, "message": "'X.y' wasn't found"}}),
        )
        .await;
        let _ = ws.next().await;
    })
    .await;
    let client = CdpClient::connect(&url, quick()).await.unwrap();
    match client.call("X.y", json!({}), None).await {
        Err(CdpError::Protocol {
            method,
            code,
            message,
        }) => {
            assert_eq!(method, "X.y");
            assert_eq!(code, -32601);
            assert!(message.contains("wasn't found"));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!client.is_closed());
}

#[tokio::test]
async fn command_timeout_fails_the_call_and_frees_the_slot() {
    let (url, _server) = fake_server(|mut ws| async move {
        // Swallow the first command, answer the second.
        let _ = next_command(&mut ws).await;
        let second = next_command(&mut ws).await.unwrap();
        send_json(&mut ws, json!({"id": second["id"], "result": {}})).await;
        let _ = ws.next().await;
    })
    .await;
    let limits = CdpLimits {
        command_timeout: Duration::from_millis(150),
        max_pending: 1,
        ..CdpLimits::default()
    };
    let client = CdpClient::connect(&url, limits).await.unwrap();
    let err = client.call("Slow.call", json!({}), None).await.unwrap_err();
    assert!(matches!(&err, CdpError::Timeout { method, .. } if method == "Slow.call"));
    assert!(matches!(
        browserx_core::Error::from(err),
        browserx_core::Error::Timeout(_)
    ));
    // max_pending is 1: the timed-out slot must have been released.
    client.call("Fast.call", json!({}), None).await.unwrap();
}

#[tokio::test]
async fn max_pending_is_enforced() {
    let (url, _server) =
        fake_server(|mut ws| async move { while next_command(&mut ws).await.is_some() {} }).await;
    let limits = CdpLimits {
        command_timeout: Duration::from_secs(5),
        max_pending: 2,
        ..CdpLimits::default()
    };
    let client = CdpClient::connect(&url, limits).await.unwrap();
    let c1 = client.clone();
    let c2 = client.clone();
    let first = tokio::spawn(async move { c1.call("A.a", json!({}), None).await });
    let second = tokio::spawn(async move { c2.call("B.b", json!({}), None).await });
    // Wait until both are registered.
    for _ in 0..200 {
        if client.inner.shared.lock().pending.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let err = client.call("C.c", json!({}), None).await.unwrap_err();
    assert!(matches!(err, CdpError::TooManyPending { limit: 2 }));
    client.close().await;
    for task in [first, second] {
        assert!(matches!(task.await.unwrap(), Err(CdpError::Closed(_))));
    }
}

#[tokio::test]
async fn events_are_broadcast_with_their_session() {
    let (url, _server) = fake_server(|mut ws| async move {
        let cmd = next_command(&mut ws).await.unwrap();
        send_json(
            &mut ws,
            json!({"method": "Target.targetCreated", "params": {"n": 1}}),
        )
        .await;
        send_json(
            &mut ws,
            json!({"method": "Page.loadEventFired", "params": {"n": 2}, "sessionId": "S9"}),
        )
        .await;
        send_json(&mut ws, json!({"id": cmd["id"], "result": {}})).await;
        let _ = ws.next().await;
    })
    .await;
    let client = CdpClient::connect(&url, quick()).await.unwrap();
    let mut first = client.events();
    let mut second = client.events();
    client
        .call("Target.setDiscoverTargets", json!({}), None)
        .await
        .unwrap();
    for rx in [&mut first, &mut second] {
        let browser_level = rx.recv().await.unwrap();
        assert_eq!(browser_level.method, "Target.targetCreated");
        assert_eq!(browser_level.session_id, None);
        let scoped = rx.recv().await.unwrap();
        assert_eq!(scoped.session_id.as_deref(), Some("S9"));
        assert_eq!(scoped.params["n"], 2);
    }
}

#[tokio::test]
async fn oversized_inbound_message_closes_the_connection() {
    let (url, _server) = fake_server(|mut ws| async move {
        let cmd = next_command(&mut ws).await.unwrap();
        let big = "x".repeat(8 * 1024);
        send_json(&mut ws, json!({"id": cmd["id"], "result": {"blob": big}})).await;
        let _ = ws.next().await;
    })
    .await;
    let limits = CdpLimits {
        max_message_bytes: 1024,
        ..quick()
    };
    let client = CdpClient::connect(&url, limits).await.unwrap();
    let err = client.call("Big.reply", json!({}), None).await.unwrap_err();
    assert!(
        matches!(err, CdpError::MessageTooLarge { limit: 1024 }),
        "{err:?}"
    );
    assert!(client.is_closed());
    assert!(matches!(
        client.call("After.close", json!({}), None).await,
        Err(CdpError::MessageTooLarge { .. })
    ));
}

#[tokio::test]
async fn oversized_outbound_command_is_refused_without_sending() {
    let (url, _server) =
        fake_server(|mut ws| async move { while next_command(&mut ws).await.is_some() {} }).await;
    let limits = CdpLimits {
        max_message_bytes: 1024,
        ..quick()
    };
    let client = CdpClient::connect(&url, limits).await.unwrap();
    let err = client
        .call("Big.send", json!({"blob": "y".repeat(4096)}), None)
        .await
        .unwrap_err();
    assert!(matches!(err, CdpError::MessageTooLarge { limit: 1024 }));
    assert!(!client.is_closed());
    assert!(client.inner.shared.lock().pending.is_empty());
}

#[tokio::test]
async fn peer_disconnect_fails_all_pending_calls() {
    let (url, _server) = fake_server(|mut ws| async move {
        let _ = next_command(&mut ws).await;
        let _ = next_command(&mut ws).await;
        drop(ws);
    })
    .await;
    let client = CdpClient::connect(&url, quick()).await.unwrap();
    let (a, b) = tokio::join!(
        client.call("A.a", json!({}), None),
        client.call("B.b", json!({}), None)
    );
    assert!(matches!(a, Err(CdpError::Closed(_))), "{a:?}");
    assert!(matches!(b, Err(CdpError::Closed(_))), "{b:?}");
    assert!(client.is_closed());
    assert!(matches!(
        client.call("C.c", json!({}), None).await,
        Err(CdpError::Closed(_))
    ));
    assert!(matches!(
        browserx_core::Error::from(CdpError::Closed("x".into())),
        browserx_core::Error::Browser(_)
    ));
}

#[tokio::test]
async fn close_sends_a_close_frame_and_is_idempotent() {
    let (tx, rx) = oneshot::channel();
    let (url, _server) = fake_server(|mut ws| async move {
        let mut saw_close = false;
        while let Some(message) = ws.next().await {
            match message {
                Ok(Message::Close(_)) => {
                    saw_close = true;
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = tx.send(saw_close);
    })
    .await;
    let client = CdpClient::connect(&url, quick()).await.unwrap();
    client.close().await;
    client.close().await;
    assert!(client.is_closed());
    assert!(rx.await.unwrap(), "server should observe a close frame");
    assert!(matches!(
        client.call("A.a", json!({}), None).await,
        Err(CdpError::Closed(_))
    ));
}

#[tokio::test]
async fn connect_failure_is_typed_and_hides_the_url() {
    let err = CdpClient::connect("ws://127.0.0.1:1/devtools/browser/SECRET-GUID", quick())
        .await
        .unwrap_err();
    assert!(matches!(&err, CdpError::Connect(_)));
    assert!(!err.to_string().contains("SECRET-GUID"));
}
