package browser

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
)

type ctxKey struct{}

func TestOpenURLWithOpener(t *testing.T) {
	t.Parallel()

	url := "https://example.com/authorize?state=s"
	errOpen := errors.New("opener error")

	tests := []struct {
		name    string
		err     error
		wantErr error
	}{
		{name: "success"},
		{name: "error_is_returned_as_is", err: errOpen, wantErr: errOpen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls int
			ctx := context.WithValue(t.Context(), ctxKey{}, tt.name)
			ctx = WithOpener(ctx, func(ctx context.Context, got string) error {
				calls++
				if got != url {
					t.Errorf("Opener URL = %q, want %q", got, url)
				}
				if v := ctx.Value(ctxKey{}); v != tt.name {
					t.Errorf("Opener context value = %v, want the caller's context (%q)", v, tt.name)
				}
				return tt.err
			})

			if err := OpenURL(ctx, url); !errors.Is(err, tt.wantErr) {
				t.Errorf("OpenURL() error = %v, want %v", err, tt.wantErr)
			}
			if calls != 1 {
				t.Errorf("Opener called %d times, want 1", calls)
			}
		})
	}
}

func TestRunCmdErrors(t *testing.T) {
	t.Parallel()

	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context //nolint:containedctx // Test table.
		cmd  string
	}{
		{name: "canceled_context", ctx: canceled, cmd: "go"},
		{name: "command_not_found", ctx: t.Context(), cmd: "versipellis-nonexistent-browser"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := runCmd(tt.ctx, tt.cmd, "version"); err == nil {
				t.Errorf("runCmd(%q) error = nil, want error", tt.cmd)
			}
		})
	}
}

// Some browser launchers run the browser in the foreground until the user closes it,
// so runCmd must return as soon as the command starts, without waiting for it to exit.
func TestRunCmdDoesNotWait(t *testing.T) {
	t.Parallel()

	const duration = 5 * time.Second
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("the sleep command isn't available on this system")
	}

	start := time.Now()
	if err := runCmd(t.Context(), "sleep", "5"); err != nil { // Plain seconds, the only portable format.
		t.Fatalf("runCmd() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed >= duration {
		t.Errorf("runCmd() returned after %v, want it to return before the command exits", elapsed)
	}
}
