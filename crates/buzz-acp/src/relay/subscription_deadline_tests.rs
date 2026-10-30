//! #6935: recover an unconfirmed subscription despite healthy ping/pong.
//! Only the relay boundary is faked; authentication, reconnect, replay, socket
//! ownership, event verification and forwarding use production code.
use super::*;

type Peer = WebSocketStream<tokio::net::TcpStream>;

async fn frame(peer: &mut Peer) -> Message {
    timeout(Duration::from_secs(3), peer.next())
        .await
        .expect("loopback response timeout")
        .expect("loopback socket closed")
        .expect("loopback frame")
}

async fn request(peer: &mut Peer) -> Value {
    loop {
        match frame(peer).await {
            Message::Ping(payload) => peer.send(Message::Pong(payload)).await.unwrap(),
            Message::Pong(_) => {}
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            other => panic!("unexpected request frame: {other:?}"),
        }
    }
}

async fn authenticate(listener: &tokio::net::TcpListener) -> Peer {
    let (stream, _) = timeout(Duration::from_secs(3), listener.accept())
        .await
        .expect("reconnect did not dial")
        .unwrap();
    let mut peer = tokio_tungstenite::accept_async(stream).await.unwrap();
    peer.send(Message::Text(
        json!(["AUTH", "6935-loopback"]).to_string().into(),
    ))
    .await
    .unwrap();
    let auth = request(&mut peer).await;
    assert_eq!(auth[0], "AUTH");
    let event: Event = serde_json::from_value(auth[1].clone()).unwrap();
    buzz_core::verify_event(&event).unwrap();
    assert_eq!(event.kind, Kind::Authentication);
    peer.send(Message::Text(
        json!(["OK", event.id.to_hex(), true, ""])
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    peer
}

/// The server Ping/Pong barrier proves that the production owner processed all
/// earlier inbound frames, including the Pong for its own heartbeat. Any REQ or
/// replacement connection during a confirmed observation window fails the test.
async fn barrier(peer: &mut Peer, listener: &tokio::net::TcpListener) -> usize {
    let marker = vec![69, 35];
    peer.send(Message::Ping(marker.clone().into()))
        .await
        .unwrap();
    let mut pings = 0;
    loop {
        let message = tokio::select! {
            _ = listener.accept() => panic!("unexpected recovery connection"),
            message = frame(peer) => message,
        };
        match message {
            Message::Ping(payload) => {
                pings += 1;
                peer.send(Message::Pong(payload)).await.unwrap();
            }
            Message::Pong(payload) if payload.as_ref() == marker => return pings,
            Message::Pong(_) => {}
            other => panic!("unexpected recovery/frame during silence: {other:?}"),
        }
    }
}

async fn send_mention(peer: &mut Peer, sub: &str, channel: Uuid, agent: &str, n: u64) -> Event {
    let event = EventBuilder::new(Kind::Custom(9), format!("mention {n}"))
        .tags([
            Tag::parse(["h", &channel.to_string()]).unwrap(),
            Tag::parse(["p", agent]).unwrap(),
        ])
        .custom_created_at(nostr::Timestamp::from(1_000 + n))
        .sign_with_keys(&Keys::generate())
        .unwrap();
    peer.send(Message::Text(
        json!(["EVENT", sub, event]).to_string().into(),
    ))
    .await
    .unwrap();
    event
}

async fn advance_clock(duration: Duration) {
    // Resume before network waits so automatic virtual-time advancement cannot
    // manufacture unrelated pong timeouts.
    tokio::time::pause();
    tokio::time::advance(duration).await;
    tokio::time::resume();
}

async fn heartbeat(peer: &mut Peer, listener: &tokio::net::TcpListener) -> usize {
    loop {
        let message = tokio::select! {
            _ = listener.accept() => panic!("unexpected recovery connection"),
            message = frame(peer) => message,
        };
        match message {
            Message::Ping(payload) => {
                peer.send(Message::Pong(payload)).await.unwrap();
                return 1 + barrier(peer, listener).await;
            }
            Message::Pong(_) => {}
            other => panic!("unexpected recovery/frame at heartbeat: {other:?}"),
        }
    }
}

#[tokio::test]
async fn missing_eose_recovers_and_confirmed_reconnect_stays_live() {
    // The fake relay ignores one replayed REQ in the recovery case. Both cases
    // must ultimately deliver on a confirmed socket without restarting the owner.
    for confirm_replay in [true, false] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let keys = Keys::generate();
        let agent = keys.public_key().to_hex();
        let connect_keys = keys.clone();
        let connect_url = url.clone();
        let connect =
            tokio::spawn(
                async move { do_connect(&connect_url, &connect_keys, None).await.unwrap() },
            );
        let mut peer = authenticate(&listener).await;
        let (ws, buffer) = connect.await.unwrap();
        let (event_tx, mut events) = mpsc::channel(8);
        let (control_tx, _controls) = mpsc::channel(1);
        let (commands, cmd_rx) = mpsc::channel(8);
        let owner = tokio::spawn(run_background_task(
            ws,
            buffer,
            event_tx,
            control_tx,
            cmd_rx,
            keys,
            url,
            agent.clone(),
            None,
        ));
        let channel = Uuid::new_v4();
        let sub = channel_sub_id(channel);
        commands
            .send(RelayCommand::Subscribe {
                channel_id: channel,
                filter: ChannelFilter {
                    kinds: Some(vec![9]),
                    require_mention: true,
                },
                replay_since: Some(1_000),
            })
            .await
            .unwrap();
        let original = request(&mut peer).await;
        assert_eq!(original[0], "REQ");
        assert_eq!(original[1], sub);
        assert_eq!(original[2]["#p"], json!([agent]));
        peer.send(Message::Text(json!(["EOSE", sub]).to_string().into()))
            .await
            .unwrap();
        let first = send_mention(&mut peer, &sub, channel, &agent, 1).await;
        let delivered = timeout(Duration::from_secs(3), events.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(delivered.event.id, first.id);
        assert_eq!(delivered.connection_generation, 0);

        // Abrupt loss drives the real autonomous reconnect and NIP-42 handshake.
        drop(peer);
        let mut peer = authenticate(&listener).await;
        let replay = request(&mut peer).await;
        assert_eq!(replay[0], "REQ");
        assert_eq!(replay[1], sub);
        assert_eq!(replay[2]["#p"], original[2]["#p"]);
        assert_eq!(replay[2]["#h"], original[2]["#h"]);
        assert_eq!(replay[2]["kinds"], original[2]["kinds"]);
        assert!(replay[2]["since"].as_u64().unwrap() <= 1_001);
        assert!(
            timeout(Duration::from_secs(3), events.recv())
                .await
                .unwrap()
                .unwrap()
                .is_none(),
            "connection-loss sentinel"
        );
        if confirm_replay {
            peer.send(Message::Text(json!(["EOSE", sub]).to_string().into()))
                .await
                .unwrap();
        }
        // Wait for paced resubscribe to return to the real read/select loop.
        let mut pings = barrier(&mut peer, &listener).await;
        if !confirm_replay {
            // History can arrive newest first. Even with partial delivery, a
            // deadline reconnect must retain the unfinished replay's old floor.
            let partial = send_mention(&mut peer, &sub, channel, &agent, 1_000).await;
            assert_eq!(
                timeout(Duration::from_secs(3), events.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap()
                    .event
                    .id,
                partial.id
            );
            // Pong is healthy at 30s, but must not suppress the EOSE deadline.
            advance_clock(PING_INTERVAL).await;
            pings += heartbeat(&mut peer, &listener).await;
            advance_clock(
                subscription_health::EOSE_TIMEOUT - PING_INTERVAL + Duration::from_secs(1),
            )
            .await;
            let mut replacement = authenticate(&listener).await;
            let retry = request(&mut replacement).await;
            assert_eq!(retry[0], "REQ");
            assert_eq!(retry[1], sub);
            assert_eq!(
                retry[2], replay[2],
                "recovery must preserve scope and cursor"
            );
            assert!(
                timeout(Duration::from_secs(3), events.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .is_none(),
                "deadline must signal connection loss"
            );
            replacement
                .send(Message::Text(json!(["EOSE", sub]).to_string().into()))
                .await
                .unwrap();
            peer = replacement;
            pings += barrier(&mut peer, &listener).await;
        }
        // More than two deadline periods after confirmation: no retry, no new
        // connection, and no stale old-socket deadline may disturb delivery.
        for _ in 0..6 {
            advance_clock(PING_INTERVAL).await;
            pings += heartbeat(&mut peer, &listener).await;
            assert!(!owner.is_finished());
            assert!(matches!(
                events.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
        assert!(pings >= 6, "heartbeat loop must actually run: {pings}");
        // A signed mention subsequently sent on the same socket is delivered:
        // silence did not wedge the reader, and no restart was needed.
        let final_event = send_mention(&mut peer, &sub, channel, &agent, 2).await;
        let delivered = timeout(Duration::from_secs(3), events.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(delivered.event.id, final_event.id);
        assert_eq!(
            delivered.connection_generation,
            if confirm_replay { 1 } else { 2 }
        );
        println!("confirm_replay={confirm_replay}: recovery={} then 180s confirmed stability, {pings} pings; signed mention delivered on generation {}", !confirm_replay, delivered.connection_generation);
        commands.send(RelayCommand::Shutdown).await.unwrap();
        timeout(Duration::from_secs(3), owner)
            .await
            .unwrap()
            .unwrap();
    }
}

async fn response(ws: &mut WsStream, state: &mut BgState, message: Value) {
    let (events, _rx) = mpsc::channel(8);
    let (controls, _control_rx) = mpsc::channel(1);
    assert!(
        handle_ws_message(
            Message::Text(message.to_string().into()),
            ws,
            &events,
            &controls,
            state,
            &Keys::generate(),
            "ws://127.0.0.1:1",
            "agent",
            None,
        )
        .await
    );
}

#[tokio::test]
async fn channel_and_control_deadlines_follow_written_requests_and_terminal_responses() {
    for kind in 0..3 {
        let (mut client, mut peer) = super::tests::test_ws_pair().await;
        let mut state = BgState::new();
        let channel = Uuid::new_v4();
        let command = || match kind {
            0 => RelayCommand::Subscribe {
                channel_id: channel,
                filter: super::tests::test_channel_filter(),
                replay_since: Some(1_000),
            },
            1 => RelayCommand::SubscribeMembership,
            _ => RelayCommand::SubscribeObserverControls,
        };
        assert!(execute_connected_command(&mut client, &mut state, "agent", command()).await);
        let req = request(&mut peer).await;
        let sub = req[1].as_str().unwrap();
        let first_deadline = state.subscription_health.deadline().unwrap();
        advance_clock(Duration::from_secs(30)).await;
        assert!(execute_connected_command(&mut client, &mut state, "agent", command()).await);
        assert_eq!(request(&mut peer).await[1], sub);
        assert_eq!(
            state.subscription_health.deadline(),
            Some(first_deadline),
            "repeated REQs must not postpone the pending deadline"
        );
        response(&mut client, &mut state, json!(["EOSE", "unrelated"])).await;
        assert_eq!(state.subscription_health.deadline(), Some(first_deadline));
        response(&mut client, &mut state, json!(["EOSE", sub])).await;
        assert!(state.subscription_health.deadline().is_none());

        assert!(execute_connected_command(&mut client, &mut state, "agent", command()).await);
        request(&mut peer).await;
        assert!(state.subscription_health.deadline().is_some());
        if kind == 0 {
            assert!(
                execute_connected_command(
                    &mut client,
                    &mut state,
                    "agent",
                    RelayCommand::Unsubscribe {
                        channel_id: channel
                    }
                )
                .await
            );
            assert_eq!(request(&mut peer).await, json!(["CLOSE", sub]));
            assert!(state.subscription_health.deadline().is_none());
            assert!(execute_connected_command(&mut client, &mut state, "agent", command()).await);
            request(&mut peer).await;
        }
        // A denial owns its retry schedule; an EOSE deadline must not force a
        // new socket while the shared rate-limit gate is deliberately closed.
        response(
            &mut client,
            &mut state,
            json!(["CLOSED", sub, "rate-limited: retry in 120s"]),
        )
        .await;
        assert!(state.subscription_health.deadline().is_none());
        assert!(state.rate_limit_gate.is_some());
        state.subscription_health.sent("stale-old-socket", None);
        let (_commands, mut commands) = mpsc::channel(8);
        assert!(matches!(
            resubscribe_after_reconnect(&mut client, &mut commands, &mut state, "agent", true,)
                .await,
            ResubscribeResult::Ok
        ));
        assert!(
            state.subscription_health.deadline().is_none(),
            "fresh socket must clear stale deadlines and not arm gated requests"
        );
        assert!(
            state.rate_limit_gate.is_some(),
            "reconnect must preserve the gate"
        );
    }
}
