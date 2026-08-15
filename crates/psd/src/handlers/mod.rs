//! HTTP handlers. `wellknown` serves the unsigned discovery documents;
//! `tokens` is the agent-facing token surface (`/person`, `/token`); `ui` is
//! the session-authenticated human surface.

pub mod mission;
pub mod tokens;
pub mod ui;
pub mod wellknown;
