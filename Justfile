clippy:
    cargo clippy --all-targets --all-features -- -D warnings

test:
    cargo test --all

run *ARGS:
    cargo run -p observerd -- {{ARGS}}
