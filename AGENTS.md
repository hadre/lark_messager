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
Keep real secrets out of version control—only commit templates like `.env.example`. Regenerate credentials with `cargo run --bin generate_credentials` and store API keys immediately; they are shown once. Never log tokens or payloads, review `.gitignore` when adding config files, record prompt executions in `prompts/prompt_records.md` to maintain traceability, and after each task append the original prompt plus a brief execution summary to that log using the established format. Record any frontend-related automation or planning prompts in `prompts/frontend_prompts_records.md` using the same template to keep UI work auditable.

## Recent Updates
- Refactored authentication to HMAC-signed API keys tied to auth_users/auth_api_keys with rate limiting, nonce caching, and failure thresholds.
- Added /auth/api-keys and /auth/configs management endpoints plus CLI bootstrap flow limited to user creation.
- Documented new workflows in README, covering canonical signing, admin bootstrap steps, troubleshooting, and updated architecture/security notes.

## Frontend Admin Console Plan
- 登录流程：登录后若`must_reset_password`为真则强制弹窗修改初始密码，成功后刷新用户信息才可进入主界面。
- 导航与权限：提供首页、API Key 管理、更改密码、消息记录查询等通用标签；管理员额外显示用户管理、配置管理、操作日志查询，基于`is_admin`控制可见性。
- 首页：作为欢迎页占位，后续可扩展统计信息。
- 用户管理：管理员可查看、创建、删除用户并重置密码；超级管理员的敏感操作按钮禁用，仅允许其自助更改密码。
- API Key 管理：展示当前用户的 Key 列表，支持创建、禁用/启用、调整限速、重置失败计数与删除；可跳转至消息记录并带上选定 Key 作为筛选。
- 配置管理：读取并编辑全局系统配置，对危险项需额外确认或只读保护。
- 更改密码：所有用户用于修改自身密码，提交当前密码与新密码即可。
- 操作日志查询：管理员按时间、用户名、用户ID、操作类型筛选平台行为记录，列表需分页并支持导出。
- 消息记录查询：按时间范围及 API Key/名称筛选历史消息，展示状态与目标信息并提供详情抽屉。
- Token 自动刷新：前端在 token 失效前5分钟触发刷新逻辑，刷新失败时提醒重新登录并处理多标签页同步。
