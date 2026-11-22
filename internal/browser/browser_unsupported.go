//go:build !darwin && !linux && !windows

package browser

import (
	"context"
	"errors"
	"runtime"
)

func startBrowser(_ context.Context, _ string) error {
	return errors.New("start browser: unsupported operating system: " + runtime.GOOS)
}
