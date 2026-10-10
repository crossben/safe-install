package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func retryServer(t *testing.T, statuses ...int) (*Client, *atomic.Int32) {
	t.Helper()
	old := retryDelay
	retryDelay = time.Millisecond
	t.Cleanup(func() { retryDelay = old })
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(calls.Add(1)) - 1
		status := http.StatusOK
		if n < len(statuses) {
			status = statuses[n]
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"name":"pkg","versions":{}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL}, &calls
}

func TestPackumentRetriesTransientErrors(t *testing.T) {
	c, calls := retryServer(t, http.StatusServiceUnavailable, http.StatusTooManyRequests)
	p, err := c.Packument(context.Background(), "pkg")
	if err != nil || p.Name != "pkg" || calls.Load() != 3 {
		t.Fatalf("got %v, %v after %d calls", p, err, calls.Load())
	}
}

func TestPackumentGivesUpAfterRetries(t *testing.T) {
	c, calls := retryServer(t, 503, 503, 503, 503)
	if _, err := c.Packument(context.Background(), "pkg"); err == nil || calls.Load() != maxRetries+1 {
		t.Fatalf("err %v after %d calls", err, calls.Load())
	}
}

func TestPackumentDoesNotRetryDefinitiveAnswers(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUnauthorized} {
		c, calls := retryServer(t, status)
		if _, err := c.Packument(context.Background(), "pkg"); err == nil || calls.Load() != 1 {
			t.Fatalf("%d: err %v after %d calls", status, err, calls.Load())
		}
	}
	c, _ := retryServer(t, http.StatusNotFound)
	if _, err := c.Packument(context.Background(), "pkg"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 = %v", err)
	}
}
