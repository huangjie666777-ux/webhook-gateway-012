# Local signed webhook service

`webhookd` receives HMAC-signed webhook events, stores them in local SQLite, and retries outbound delivery with transaction-safe state. It uses only Chi, `modernc.org/sqlite`, and Go standard-library infrastructure.

## Run

```sh
go run ./cmd/webhookd \
  -addr :8080 \
  -db ./webhook.db \
  -delivery-timeout 10s \
  -worker-interval 1s
```

The same settings can be supplied with `WEBHOOK_ADDR` and `WEBHOOK_DB`. SIGTERM/SIGINT triggers graceful HTTP shutdown; deliveries already claimed are reset to `pending` on the next startup.

Inbound requests are limited to 1 MiB. Event timestamps may differ from server time by at most five minutes. Signing input is exactly `X-Webhook-Timestamp` + `.` + the raw request body, signed with HMAC-SHA256 and sent as lowercase hex.

## Endpoint setup

```sh
curl -sS -X POST http://localhost:8080/v1/endpoints \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant":"tenant-a",
    "id":"payments",
    "url":"http://127.0.0.1:9000/hook",
    "key_id":"key-1",
    "secret":"top-secret"
  }'

curl -sS -X POST http://localhost:8080/v1/endpoints/payments/keys \
  -H 'Content-Type: application/json' \
  -d '{
    "tenant":"tenant-a",
    "key_id":"key-2",
    "secret":"new-secret"
  }'
```

Key rotation deactivates all existing keys for that endpoint and activates the new key.

## Send a signed event

```sh
BODY='{"event":"payment.created","id":"evt-1001"}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac 'new-secret' | sed 's/^.*= //')

curl -sS -X POST http://localhost:8080/v1/endpoints/payments/events \
  -H 'X-Tenant-Id: tenant-a' \
  -H "X-Webhook-Id: evt-1001" \
  -H "X-Webhook-Timestamp: $TS" \
  -H 'X-Webhook-Key-Id: key-2' \
  -H "X-Webhook-Signature: $SIG" \
  -H 'X-Webhook-Ordering-Key: customer-42' \
  --data-raw "$BODY"
```

The same endpoint and event ID with the same body is idempotent; a different body returns HTTP 409. Failed signature, key, or timestamp validation does not create a database row. Events sharing an `X-Webhook-Ordering-Key` are delivered in received order, one at a time.

## Query and replay

```sh
curl -sS http://localhost:8080/v1/endpoints/payments/events \
  -H 'X-Tenant-Id: tenant-a'

curl -sS -X POST http://localhost:8080/v1/endpoints/payments/events/evt-1001/replay \
  -H 'X-Tenant-Id: tenant-a'

curl -sS http://localhost:8080/healthz
```

Outbound requests POST the original raw body and include `X-Event-Id` plus a 1-based `X-Webhook-Attempt`. 2xx marks the delivery succeeded; network errors, timeouts, and 5xx use deterministic exponential backoff. Non-retryable failures and attempts past the maximum become `dead`, and replay returns them to the queue.

Errors consistently use JSON fields `code`, `message`, and `request_id`; the matching `X-Request-Id` response header is also returned. Logs include request/status identifiers only and never log signing secrets or event payloads.
