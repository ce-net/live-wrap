//! `ce wrap <app>`: a catalog entry per app, the passkey forward-auth in front of it (default deny), and snapshot
//! and restore of its state.
pub mod auth;
pub mod catalog;
pub mod snapshot;
