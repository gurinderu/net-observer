# `--all`, not the default members: without it clippy silently skips
# net-observer-bar, which is how a type-complexity error reached CI green-looking.
clippy:
    cargo clippy --all --all-targets --all-features -- -D warnings

test:
    cargo test --all

run *ARGS:
    cargo run -p net-observerd -- {{ARGS}}

# The WHOLE local gate as one call — never assemble the steps by hand: a
# hand-built chain silently drops a step and still ends green. Run inside
# `nix develop` (the bar only compiles there; on a Linux box the darwin-only
# halves stay CI's claim — use the per-crate carriers from AGENTS.md, Reality).
gate:
    cargo fmt --all -- --check
    cargo build --all
    cargo test --all
    cargo clippy --all --all-targets --all-features -- -D warnings
