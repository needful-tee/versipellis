// Package sandbox provides utilities for skipping tests in sandboxed environments.
// Only tests should import this package, but it has no tests of its own.
package sandbox

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// loopbackErr checks whether the environment supports loopback TCP connections, by attempting to listen on a
// random local port and dialing it. Some sandboxes allow listening but not dialing, so checking both is necessary.
var loopbackErr = sync.OnceValue(func() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	conn, err := new(net.Dialer).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	_ = conn.Close()
	return nil
})

// CheckLoopback returns an error if the environment doesn't support loopback TCP connections.
// It performs the check lazily, only once per process, and caches the result.
func CheckLoopback(tb testing.TB) error {
	tb.Helper()
	return loopbackErr()
}

// RequireLoopback skips the calling test in environments without loopback TCP (e.g., sandboxes),
// instead of failing or timing out. Skipped tests aren't verified, so the message says how to
// verify them. It performs the check lazily, only once per process, and caches the result.
func RequireLoopback(tb testing.TB) {
	tb.Helper()
	if err := loopbackErr(); err != nil {
		tb.Skipf("needs loopback (listen and dial); run outside the sandbox to verify: %v", err)
	}
}
