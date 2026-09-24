# Webhook gateway

A local, self-contained signed-webhook receiver with durable, ordered and
recoverable outbound delivery. Storage is a single SQLite file (pure-Go
`modernc.org/sqlite`); there are no cloud services or external databases.

## Features

- Endpoint creation and tenant isolation via `X-Tenant-Id`.
- HMAC-SHA256 signing keys with create/rotate/retire; key secrets are shown
  exactly once and never logged.
- Signed inbound events: headers `X-Webhook-Id`, `X-Webhook-Timestamp`,
  `X-Webhook-Key-Id`, `X-Webhook-Signature`; the signed string is
  `timestamp + "." + raw body`. Verification uses constant-time comparison and
  a timestamp-skew window (default 5 minutes); only active keys are accepted.
- Idempotent submission: identical `(endpoint, event id, content)` repeats are
  accepted without new state; reused ids with different content return `409`.
- Failed verification writes nothing.
- Durable delivery worker: sends the original raw body with
  `X-Webhook-Event-Id` and `X-Webhook-Attempt`. Network errors, timeouts and
  5xx (plus 408/429) retry with deterministic exponential backoff
  (`initial * 2^(attempt-1)`, capped). Exhausted events become `dead` and can
  be replayed.
- Events sharing `X-Webhook-Ordering-Key` are delivered in receive order,
  including after failures and restarts (stale in-flight deliveries are
  recovered).
- Request body limit (1 MiB), per-endpoint unfinished-event cap (1000),
  SSRF-safe endpoint URLs (loopback/private/link-local blocked unless
  `--allow-private-url`), no-redirect outbound client, stable ordering, and
  structured error JSON: `{"code","message","request_id"}`.

## Run

```bash
go run ./cmd/webhookd -addr :8080 -db ./webhookd.db
# local development against a loopback receiver:
go run ./cmd/webhookd -addr :8080 -db ./webhookd.db --allow-private-url
```

Graceful shutdown on `SIGINT`/`SIGTERM` stops accepting HTTP requests, waits
for in-flight deliveries, and records their outcomes before exiting.

## curl walkthrough

```bash
# 1. Create an endpoint and its first key (secret is returned once).
curl -s -X POST http://localhost:8080/v1/endpoints \
  -H 'X-Tenant-Id: tenant-a' -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:9099/hook"}'
# -> {"endpoint":{"id":"ep_...","url":"..."},"key":{"id":"key_...","secret":"..."}}

EP=ep_xxx; KEY=key_xxx; SECRET=xxxxxxxxxxxxxxxx

# 2. Rotate keys ("rotate":true retires existing active keys).
curl -s -X POST http://localhost:8080/v1/endpoints/$EP/keys \
  -H "X-Tenant-Id: tenant-a" -H 'Content-Type: application/json' -d '{"rotate":true}'

# 3. Send a signed event.
BODY='{"order":42}'
TS=$(date +%s)
SIG=$(printf '%s' "$TS.$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')
curl -s -X POST http://localhost:8080/v1/endpoints/$EP/events \
  -H "X-Webhook-Id: evt-1" \
  -H "X-Webhook-Timestamp: $TS" \
  -H "X-Webhook-Key-Id: $KEY" \
  -H "X-Webhook-Signature: $SIG" \
  -H 'X-Webhook-Ordering-Key: order-42' \
  -H 'Content-Type: application/json' \
  --data-raw "$BODY"

# 4. Query events / one event, and replay a dead or failed event.
curl -s "http://localhost:8080/v1/endpoints/$EP/events?limit=50" -H 'X-Tenant-Id: tenant-a'
curl -s http://localhost:8080/v1/endpoints/$EP/events/evt-1 -H 'X-Tenant-Id: tenant-a'
curl -s -X POST http://localhost:8080/v1/endpoints/$EP/events/evt-1/replay -H 'X-Tenant-Id: tenant-a'

# 5. Health.
curl -i http://localhost:8080/healthz
```

Errors always use the stable envelope, e.g.:

```json
{"code":"invalid_signature","message":"signature verification failed","request_id":"req_..."}
```

## Develop

```bash
gofmt -w .
go test ./...
go vet ./...
go build ./cmd/webhookd
```
