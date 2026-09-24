package webhook

import "context"

// Status is the lifecycle state of an inbound event or outbound delivery.
type Status string

const (
	StatusPending    Status = "pending"
	StatusDelivering Status = "delivering"
	StatusSucceeded  Status = "succeeded"
	StatusRetrying   Status = "retrying"
	StatusDead       Status = "dead"
)

// Event is a signed inbound webhook accepted for an endpoint.
type Event struct {
	ID         string
	EndpointID string
	EventKey   string
	Payload    []byte
	Signature  string
	KeyID      string
	ReceivedAt int64
	Status     Status
}

// Endpoint describes a destination and its active verification keys.
type Endpoint struct {
	ID     string
	Tenant string
	URL    string
	Active bool
}

// Delivery is the durable attempt state for one event.
type Delivery struct {
	EventID     string
	Attempt     int
	NextAttempt int64
	Status      Status
	LastCode    int
	LastError   string
}

// WebhookStore is the public storage boundary used by the HTTP layer and worker.
type WebhookStore interface {
	Accept(context.Context, string, string, []byte, string, string) (Event, bool, error)
	Claim(context.Context, string, int) ([]Delivery, error)
	Complete(context.Context, string, int, int, string) error
}
