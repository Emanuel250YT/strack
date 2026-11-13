//! Strack: a federal platform for live blocking orders against pirate football streams.
//!
//! The platform builds a verifiable case file for every detected stream, routes it to the judge on
//! duty, sends the signed order to every internet provider in the type each one accepts, follows
//! their confirmation (retrying failures), lets IP blocks expire at the end of the match, handles
//! claims from legitimate sites and keeps a hash-chained audit log plus a public transparency registry.
//! Leak tracing reads the session mark of a licensed stream from a pirate copy and asks the licensed
//! platform to suspend the subscriber who leaks it (`leak`), with demo servers for both sides (`demo`).

pub mod access;
pub mod admin;
pub mod app;
pub mod audit;
pub mod cli;
pub mod clock;
pub mod crypto;
pub mod demo;
pub mod engine;
pub mod evidence;
pub mod export;
pub mod intake;
pub mod judges;
pub mod leak;
pub mod model;
pub mod provider;
pub mod simulator;
pub mod standalone;
pub mod web;
pub mod workflow;
