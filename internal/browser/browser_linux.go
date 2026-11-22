package browser

import (
	"context"
	"os/exec"
)

func startBrowser(ctx context.Context, url string) error {
	for _, provider := range []string{"xdg-open", "x-www-browser"} {
		if _, err := exec.LookPath(provider); err == nil {
			return runCmd(ctx, provider, url)
		}
	}
	return &exec.Error{Name: "xdg-open,x-www-browser", Err: exec.ErrNotFound}
}
