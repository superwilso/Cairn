//! # cairn-client-core
//!
//! Everything a Cairn client does that is not drawing pixels: MLS session management,
//! the franking chain, envelope construction, and tier enforcement.
//!
//! ## Why this crate exists
//!
//! Cairn targets native clients on Windows, macOS, Linux, iOS, and Android
//! (`docs/09-platform-strategy.md`). Reimplementing the protocol five times would
//! guarantee five different sets of security bugs. Instead this crate holds all of it,
//! compiles to every target, and each platform binds to it through a thin FFI layer with
//! a native UI on top.
//!
//! **This crate must never gain a UI dependency.** That is the property that keeps it
//! portable.

#![forbid(unsafe_code)]

pub mod conversation;
pub mod store;

pub use conversation::{
    Conversation, ConversationError, OutboundMessage, ReceivedFranking, ReceivedMessage,
};
pub use store::{ConversationIndex, ConversationRecord, IndexError};
