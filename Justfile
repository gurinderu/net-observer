# `--all`, not the default members: without it clippy silently skips
# net-observer-bar, which is how a type-complexity error reached CI green-looking.
clippy:
    cargo clippy --all --all-targets --all-features -- -D warnings

test:
    cargo test --all

run *ARGS:
    cargo run -p net-observerd -- {{ARGS}}
