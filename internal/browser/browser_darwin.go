package browser

import (
	"context"
)

func startBrowser(ctx context.Context, url string) error {
	return runCmd(ctx, "open", url)
}
