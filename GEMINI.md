# Gemini & Antigravity Instructions

Follow [`AGENTS.md`](./AGENTS.md) for architecture, coding practices, and concurrency invariants.

When reviewing code, commits, PRs, or diffs, read and follow [`REVIEW.md`](./REVIEW.md) as well.

## Antigravity Environment Guidelines

- **Sandbox execution:** Commands run in Antigravity's standard sandbox (`BypassSandbox: false`) by default without loopback socket access.
  - Run unit and race tests inside the sandbox. Socket-dependent tests (e.g., in `pkg/http` and `pkg/auth`) detect the sandbox and skip themselves:

    ```shell
    go test -timeout 30s -v -race ./pkg/...
    ```

  - Check the output for `--- SKIP` lines: skipped tests are unverified.
  - Use `BypassSandbox: true` only when loopback network socket access is strictly necessary, preferring direct command shapes:
    - Verifying skipped tests: rerun the packages that reported them, e.g., `go test -timeout 30s -v -race ./pkg/http ./pkg/auth`
- **Command execution:**
  - Commands always execute in the workspace root; do not attempt to pass a `Cwd` parameter. Run commands against target paths directly (e.g., `go test ./pkg/...`).
  - Set `WaitMsBeforeAsync: 10000` for test suites and builds so they complete synchronously instead of backgrounding.
  - Never run `sleep` in background commands; use Antigravity's `schedule` tool or non-blocking mechanisms.
- **Code modifications & Testing:**
  - Prefer surgical replacements (`edit_file`) over whole-file rewrites whenever possible.
  - After modifying Go code, always run `golangci-lint fmt && golangci-lint run`.
  - Timing-dependent tests must use Go 1.27's `testing/synctest` rather than wall-clock `time.Sleep`.
- **Communication & Reviews:**
  - Always link referenced files with absolute URLs and line anchors, e.g., `[client.go](file:///path/versipellis/pkg/http/client.go#L50-L75)`.
