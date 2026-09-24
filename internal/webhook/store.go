package webhook

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("webhook store is not implemented in the initial skeleton")

type MemoryStore struct{}

func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

func (s *MemoryStore) Accept(context.Context, string, string, []byte, string, string) (Event, bool, error) {
	return Event{}, false, ErrNotImplemented
}
func (s *MemoryStore) Claim(context.Context, string, int) ([]Delivery, error) {
	return nil, ErrNotImplemented
}
func (s *MemoryStore) Complete(context.Context, string, int, int, string) error {
	return ErrNotImplemented
}
