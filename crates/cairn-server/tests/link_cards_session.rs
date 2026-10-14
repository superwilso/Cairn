//! Link cards through a real instance and the session layer the desktop client delegates
//! to.
//!
//! The property that matters most is the recipient's: **receiving and showing a card
//! contacts nothing**. Each test points every URL on the card at a loopback listener and
//! afterwards asks whether anything connected to it. A client that resolved a received
//! link to draw its card — the leak `docs/05-embeds.md` exists to prevent — fails here.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cairn_client_core::embed::{Card, Sites, Thumbnail};
use cairn_client_core::session::{Event, LinkPreviewSettings, MessageView, Session};
use cairn_server::state::{Instance, RegistrationPolicy};

struct Server {
    addr: SocketAddr,
    _runtime: tokio::runtime::Runtime,
}

fn start() -> Server {
    let instance = Arc::new(Instance::in_memory());
    instance.set_registration_policy(RegistrationPolicy::Open).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let router = cairn_server::http::router(instance);
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });
    Server { addr, _runtime: runtime }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cairn-cards-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn session_in(server: &Server, name: &str, dir: &Path) -> Session {
    Session::open(name, &format!("http://{}", server.addr), Some(dir)).unwrap()
}

fn two_in_a_group(server: &Server) -> (Session, Session, PathBuf, String) {
    let mut alice = session_in(server, "alice", &scratch("alice"));
    let bob_dir = scratch("bob");
    let mut bob = session_in(server, "bob", &bob_dir);
    bob.publish_key_packages(3).unwrap();
    let room = alice.create_group(10).unwrap();
    let token = alice.create_invite(1, 24).unwrap();
    bob.redeem_invite(&token).unwrap();
    alice.admit_waiting().unwrap();
    bob.open_room(&room).unwrap();
    bob.poll().unwrap();
    (alice, bob, bob_dir, room)
}

fn hear(session: &mut Session, body: &str) -> MessageView {
    for _ in 0..6 {
        for event in session.poll().unwrap() {
            if let Event::Message(m) = event {
                if m.body == body {
                    return m;
                }
            }
        }
    }
    panic!("never heard {body:?}")
}

/// A loopback listener standing in for "the site the link points at", and a way to ask
/// whether anyone contacted it. Non-blocking, so "nobody did" is an answer, not a timeout.
struct Site(TcpListener);

impl Site {
    fn new() -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        Self(l)
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.0.local_addr().unwrap())
    }
    fn was_contacted(&self) -> bool {
        self.0.accept().is_ok()
    }
}

/// A card whose every URL — the link and the image — points at `site`.
fn card_for(site: &Site) -> Card {
    Card {
        url: site.url("/reel/abc"),
        title: Some("A headline".into()),
        description: Some("What the page says.".into()),
        site_name: Some("Example".into()),
        image_url: Some(site.url("/img.jpg")),
        thumbnail: Some(Box::new(Thumbnail {
            mime: "image/jpeg".into(),
            width: 9,
            height: 16,
            // FF D8 FF E0: enough of a JPEG to pass the receipt check.
            data: "/9j/4A==".into(),
        })),
        ..Card::default()
    }
}

#[test]
fn a_recipient_shows_a_card_without_contacting_anything() {
    let server = start();
    let (mut alice, mut bob, bob_dir, room) = two_in_a_group(&server);
    let site = Site::new();
    let card = card_for(&site);
    let body = format!("look {}", card.url);

    let pending = alice.begin_send(&body, None).unwrap().with_card(card);
    let sent = alice.finish_send(pending).unwrap();
    assert!(sent.card.is_some(), "the sender sees their own card at once");

    let heard = hear(&mut bob, &body);
    let view = heard.card.expect("the card travelled inside the message");
    assert_eq!(view.title.as_deref(), Some("A headline"));
    assert!(
        view.thumbnail.as_deref().is_some_and(|t| t.starts_with("data:image/jpeg;base64,")),
        "the image reaches the UI as bytes that came in the message, never as a URL"
    );
    assert!(!site.was_contacted(), "receiving a card must not contact the site");

    // And a restart, which replays the transcript, does not either.
    drop(bob);
    let mut bob = session_in(&server, "bob", &bob_dir);
    let replayed = bob.open_room(&room).unwrap();
    let again = replayed.iter().find(|m| m.body == body).expect("the message survives");
    assert!(again.card.is_some(), "a reopened room shows the card again");
    assert!(!site.was_contacted(), "replaying a card must not contact the site either");
}

#[test]
fn a_card_for_a_link_the_message_does_not_contain_is_not_shown_to_the_recipient() {
    // A modified client can attach a card for one link to a message containing another.
    // The recipient clicks the link in the text, so a card for anything else is a disguise.
    let server = start();
    let (mut alice, mut bob, _, _) = two_in_a_group(&server);
    let site = Site::new();
    let body = "read this https://evil.test/world".to_string();
    let pending = alice.begin_send(&body, None).unwrap().with_card(card_for(&site));
    alice.finish_send(pending).unwrap();

    let heard = hear(&mut bob, &body);
    assert!(heard.card.is_none(), "a card for some other link must be dropped");
    assert!(!site.was_contacted());
}

#[test]
fn by_default_the_sender_contacts_nothing() {
    // No setting touched: previews are off for every site, so a pasted link is not fetched.
    let server = start();
    let (mut alice, _bob, _, _) = two_in_a_group(&server);
    assert_eq!(alice.link_previews(), LinkPreviewSettings::default());
    let site = Site::new();
    let body = format!("look {}", site.url("/page"));

    let mut pending = alice.begin_send(&body, None).unwrap();
    assert_eq!(pending.preview_url(), None, "off means no fetch is even planned");
    pending.unfurl();
    let sent = alice.finish_send(pending).unwrap();
    assert!(sent.card.is_none());
    assert!(!site.was_contacted(), "previews off must mean the link is never fetched");
}

#[test]
fn a_switched_off_platforms_link_produces_no_network_request() {
    // Every switch on except the one this link falls under ("other websites": a loopback
    // listener is not a named platform). Turning the others on must not leak into it.
    let server = start();
    let (mut alice, _bob, _, _) = two_in_a_group(&server);
    let everything_but_web = Sites { web: false, ..Sites::all() };
    alice
        .set_link_previews(LinkPreviewSettings { sites: everything_but_web, instagram_proxy: true })
        .unwrap();
    let site = Site::new();
    let body = format!("look {}", site.url("/page"));

    let mut pending = alice.begin_send(&body, None).unwrap();
    assert_eq!(pending.preview_url(), None, "a switched-off site is not planned");
    pending.unfurl();
    let sent = alice.finish_send(pending).unwrap();
    assert!(sent.card.is_none());
    assert!(!site.was_contacted(), "a switched-off site must receive no request at all");

    // The same holds for a named platform: Instagram off, its proxy switch on — nothing is
    // planned, so neither Instagram nor the proxy is asked.
    alice
        .set_link_previews(LinkPreviewSettings {
            sites: Sites { instagram: false, ..Sites::all() },
            instagram_proxy: true,
        })
        .unwrap();
    let pending = alice.begin_send("https://www.instagram.com/reel/C5nYxQyOZ6V/", None).unwrap();
    assert_eq!(pending.preview_url(), None);
}

#[test]
fn a_link_to_the_senders_own_network_is_never_fetched() {
    // Previews on for this kind of link, and the link points at loopback: the address
    // policy, not a setting, is what keeps a pasted link from probing the sender's machine.
    let server = start();
    let (mut alice, _bob, _, _) = two_in_a_group(&server);
    alice
        .set_link_previews(LinkPreviewSettings {
            sites: Sites { web: true, ..Sites::default() },
            instagram_proxy: false,
        })
        .unwrap();
    let site = Site::new();
    let body = format!("look {}", site.url("/admin"));

    let mut pending = alice.begin_send(&body, None).unwrap();
    assert!(pending.preview_url().is_some(), "previews are on, so a fetch is planned");
    pending.unfurl();
    let sent = alice.finish_send(pending).unwrap();
    assert!(sent.card.is_none());
    assert!(!site.was_contacted(), "a loopback link must be refused before connecting");
}
