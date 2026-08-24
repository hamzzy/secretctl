# M1-M3 implementation coverage

This matrix compares the implementation to the normative requirements in
`secretctl-technical-prd.md`. A compiling crate or mock-mode test is not counted
as an acceptance pass.

## Fixed during this audit

- Credential secrets are no longer accepted through CLI arguments. They are
  read with a no-echo prompt, wrapped in zeroizing memory, stored under an
  opaque provider locator, and paired with SQLite metadata.
- Action requests resolve stored credential metadata and allowed actions rather
  than treating the public identity name as a keychain locator.
- Broker decisions use a fresh page context measured by the browser runtime.
  Requested, policy, and recipe path constraints are evaluated against the
  executor-measured URL path; only its SHA-256 digest is retained for audit.
  Capabilities bind the extension key, session, tab, frame, document,
  navigation epoch, exact origins, recipe/hash, and policy hash.
- Missing or disabled recipes fail closed. Recipe selectors, field roles, and
  submit behavior now drive executor output; the broker no longer invents
  selectors. Runtime recipe deserialization now matches the published nested
  schema and rejects unknown keys.
- Request IDs are idempotent for identical requests and conflict when reused
  with different parameters.
- Required approvals have persisted pending/approved/denied/expired state,
  context-digest validation, user-presence enforcement, and no mint on denial.
- Policy reload and stale browser heartbeat paths revoke active capabilities.
- The CDP filter denies unknown methods by default and blocks raw evaluation,
  response bodies, cookies/storage, screenshots, AX/DOM snapshots, and other
  credential-extraction surfaces as required by sensitive-window state.
- Page-controlled `window.postMessage` is no longer an execution channel. The
  extension uses extension-only runtime messaging, verifies field uniqueness,
  editability, visibility, viewport/hit-test safety, exact form-action origin,
  and element stability, then clears values on failure.
- TypeScript and Python clients perform `session.hello`, verify the broker's
  Ed25519 handshake signature, reject secret-bearing response keys, and expose
  execute/status/cancel. Python public models reject unknown fields and include
  the required dedicated-loop synchronous wrapper.
- MCP exposes only `secretctl_execute`, `secretctl_action_status`, and
  `secretctl_cancel_action` with closed schemas.
- SQLite enables WAL, foreign keys, and a busy timeout. CLI audit verification
  now reads and verifies the actual stored chain. Fake status/health success
  messages were replaced with live checks.

## Milestone status

### M1 - partial, not exited

Implemented and locally verified: daemon socket separation and permissions,
credential metadata/provider lookup, macOS provider adapter, policy evaluation,
approval decision flow, capability mint/consume, audit persistence and chain
verification, heartbeat and policy revocation, no-secret CLI input, and fake
executor lifecycle tests.

Release blockers:

- Agent enrollment authenticates an enrolled ID and the server handshake, but
  does not yet require a client signature over the broker nonce or verify OS
  peer executable identity.
- Executor enrollment/session signatures are not verified, and the native-host
  bridge is not an encrypted authenticated channel.
- Capability consume, execution creation, and audit append are not yet one
  durable SQLite transaction. Restart recovery cannot therefore prove AT-15.
- The audit chain detects mutation/reordering but is SHA-256 chained rather than
  the required versioned HMAC with signed checkpoints and key rotation.
- Most normative CLI/admin commands remain absent, including daemon lifecycle,
  approval watch/approve/deny, capability list/revoke, audit export, policy
  explain/reload, browser commands, and installation helpers.
- AT-14, AT-16, AT-17, AT-19, and the real-keychain portion of AT-20 have not
  been executed as release acceptance tests.

### M2 - partial, not exited

Implemented and locally verified: Chromium argument construction with a private
debugging pipe, default-deny CDP filtering/redaction, native-message framing,
MV3 extension scaffolding, and isolated-world field preflight/execution logic.

Release blockers:

- `BrowserGateway` is a filter object, not a running constrained automation
  service or CDP relay. The Chrome debugging pipe is not connected to it.
- Browser launch/session registration, extension pairing/attestation, execution
  offer/prepare/commit, encrypted one-time secret envelope, sensitive-window
  gateway coordination, and result delivery are not connected end to end.
- The extension still uses broad development host permissions and has no
  packaged identity/version compatibility enforcement.
- No packaged-Chromium E2E fixture or adversarial canary scan exists. Therefore
  AT-01, AT-03 through AT-10, AT-15, and AT-18 are not acceptance passes.

### M3 - partial, not exited

Implemented and locally verified: buildable TypeScript SDK, strict Python SDK,
MCP adapter shape, RFC 6238 generation, TOTP broker execution, aggregate
sensitive-form recipe roles, examples, and hostile-response unit tests.

Release blockers:

- The SDKs do not yet complete client nonce signing, encrypted IPC, reconnect,
  subscriptions/event ordering, or live broker contract fixtures.
- TOTP near-boundary waiting is broker coordinated, but duplicate-step issuance
  limits are not durably tracked. Sensitive-form plaintext values are serialized
  on the executor RPC instead of a one-time encrypted envelope.
- There are no extension/browser side-channel E2E canary tests for TOTP or
  multi-field forms and no live Python/MCP managed-browser acceptance run.
  Consequently AT-02 and AT-11 are not acceptance passes.

## Verification currently available

- `cargo test --workspace --all-targets`
- `npm run build && npm test` in `sdk/typescript`
- `npm run build` in `integrations/mcp`
- `uv run --with pydantic --with cryptography --with pytest --with pytest-asyncio pytest -q`
  in `sdk/python`

These checks validate implemented units and fake-executor integration only. They
must not be reported as M1, M2, or M3 release acceptance.
