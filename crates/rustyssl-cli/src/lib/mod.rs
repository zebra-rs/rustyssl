//! The commands' shared code, ported from upstream's `apps/lib` (ADR 0007, section 5).
//!
//! Command forks don't edit these modules: a new shared helper goes in the command's own file
//! first, and moves here afterwards.

// Ported for the command forks (G1-G6); F0's commands use only part of it.
#![allow(dead_code)]

pub mod app_libctx;
pub mod app_rand;
pub mod apps;
pub mod engine;
pub mod io;
pub mod opt;
pub mod s_cb;
pub mod s_socket;

#[cfg(test)]
mod live_tests;
