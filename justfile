default:
    @just --list

# Build all workspace targets
build:
    cargo build --workspace --all-targets

# Run all workspace tests
test:
    cargo test --workspace

# Check formatting and clippy lints
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Run strict security lints
deny:
    cargo deny check
