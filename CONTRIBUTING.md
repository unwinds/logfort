# Contributing to LogFort

Thank you for your interest in contributing!

## Development setup

```bash
git clone https://github.com/unwinds/logfort
cd logfort
go mod download
go test ./...
```

## Running locally

```bash
# Point at a real auth.log (read-only)
LOGFORT_LOG_PATHS=/var/log/auth.log \
LOGFORT_DB_PATH=/tmp/logfort-dev.db \
LOGFORT_LISTEN=127.0.0.1:8080 \
go run ./cmd/logfort
```

## Code standards

- Idiomatic Go: `gofmt`, `goimports`, passes `golangci-lint`
- `context.Context` threaded through all functions
- Errors wrapped with `%w`; no `panic` in runtime paths
- Structured logging via `log/slog`
- No global state; dependencies via constructors

## Commit convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add GeoIP lookup
fix: handle December→January timestamp rollover
test: add fixture for RHEL auth log format
docs: update quickstart docker-compose example
chore: bump modernc.org/sqlite to v1.54
```

## Adding parser patterns

Parser test fixtures live in `testdata/`. When you encounter an unparsed
log line:

1. Add the raw line to the appropriate fixture file.
2. Add a test case in `internal/parse/parser_test.go`.
3. Add or extend a regex in `internal/parse/parser.go`.
4. Run `go test -race ./internal/parse/...`.

## Pull request checklist

- [ ] `go test -race ./...` passes
- [ ] New behaviour is covered by tests
- [ ] Commit messages follow Conventional Commits
- [ ] No new external dependencies without justification
