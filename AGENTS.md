# Repository Guidelines

## Project Structure & Module Organization
Service modules live in `src/`, grouped by domain (auth, messaging, persistence, HTTP handlers). Integration and unit suites reside in `tests/`, SQL migrations in `migrations/`, prompt assets and required session logs in `prompts/`, and runnable demos in `examples/`. Operational helpers such as `Dockerfile`, `docker-compose.yml`, and `scripts/` support deployment and local tooling.

## Architecture Overview
An Axum-based REST API fronts the Lark Bot API, persisting users, API keys, and message logs in MySQL via SQLx. Dual authentication is standard: short-lived JWTs for human users, long-lived hashed API keys for trusted services. A validator normalises recipient identifiers (email, mobile, chat names) before dispatch, while structured tracing captures request metadata. Keep the audit trail complete by appending automation results to `prompts/prompt_records.md` using the documented markdown template.

## Build, Test, and Development Commands
Run `cargo check` for a quick sanity pass, `cargo build` or `cargo run` to compile and launch the API on port 8080, and `cargo run --bin generate_credentials` to bootstrap admins or API keys. Enforce formatting with `cargo fmt` and treat `cargo clippy --all-targets -- -D warnings` as a gate. Preferred test entry point is `./scripts/run_tests.sh`, which honours `TEST_DATABASE_URL`; `docker-compose up --build` reproduces the service stack and can be validated with `curl http://localhost:8080/health`.

## Coding Style & Naming Conventions
Stick to Rust defaults: four-space indentation, `snake_case` for functions and modules, `CamelCase` for types, screaming-snake constants. Mirror directory layout when adding DTOs or route handlers, document complex flows with concise `///` comments, and do not ignore clippy feedback.

## Testing Guidelines
Prepare a dedicated MySQL schema and export `TEST_DATABASE_URL` (or source `.env.test`) before running suites. Name cases descriptively (e.g., `test_message_dispatch_fails_without_token`) and add integration coverage whenever HTTP flows or migrations change. Share fixtures under `tests/common/` so they are reusable across suites.

## Commit & Pull Request Guidelines
Follow the existing conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`) with imperative summaries. Pull requests must outline intent, surface schema or config impacts, and link related tickets. Attach curl snippets or screenshots for UX/API shifts and confirm fmt, clippy, and tests in the description.

## Configuration, Security & Logging
Keep real secrets out of version control—only commit templates like `.env.example`. Regenerate credentials with `cargo run --bin generate_credentials` and store API keys immediately; they are shown once. Never log tokens or payloads, review `.gitignore` when adding config files, and record prompt executions in `prompts/prompt_records.md` to maintain traceability.

## Recent Updates
- Refactored authentication to HMAC-signed API keys tied to auth_users/auth_api_keys with rate limiting, nonce caching, and failure thresholds.
- Added /auth/api-keys and /auth/configs management endpoints plus CLI bootstrap flow limited to user creation.
- Documented new workflows in README, covering canonical signing, admin bootstrap steps, troubleshooting, and updated architecture/security notes.
