//! Feasibility spike: capture the TLS 1.3 `handshake_secret` from an unmodified
//! rustls `ClientConnection` via a custom `rustls::crypto::tls13::Hkdf` wrapper.
//!
//! See `specs/spikes/tls13-secret-capture.md`. This is throwaway prototype code:
//! it leaks a few `'static` allocations on purpose and panics liberally.
//!
//! Run with: `cargo run -p tls13-secret-capture`
//!
//! Exit code is 0 iff every §3.2 assertion passed.

mod capture;
mod harness;
mod verify;

use std::process::ExitCode;

fn main() -> ExitCode {
    let outcome = harness::run();

    println!("\n================ SPIKE RESULT ================");
    let mut all_pass = true;
    for a in &outcome.assertions {
        let tag = if a.pass { "PASS" } else { "FAIL" };
        println!("[{tag}] {}", a.name);
        if !a.pass {
            all_pass = false;
            if let Some(detail) = &a.detail {
                println!("        {detail}");
            }
        }
    }
    println!("==============================================");
    if all_pass {
        println!("OVERALL: PASS  (wrapper approach is viable on rustls 0.23.40)");
        ExitCode::SUCCESS
    } else {
        println!("OVERALL: FAIL");
        ExitCode::FAILURE
    }
}
