//! Test shim. The actual SDBL v3 reader lives at
//! [`dns_blocklist_compiler::reader`] so the builder can run round-trip
//! validation at build time. This re-export preserves the historical
//! `common::binary_reader::*` import path used by integration tests.

pub use dns_blocklist_compiler::reader::*;
