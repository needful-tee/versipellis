package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"needful-t.ee/versipellis/internal/browser"
)

const (
	// CallbackTimeout is the maximum amount of time to wait for the user to complete an OAuth Authorization Code flow,
	// i.e. until we receive a redirected callback from the OAuth provider containing a temporary authorization code.
	CallbackTimeout = time.Minute

	// RequestTimeout is the maximum amount of time to wait for each HTTP request in OAuth flows to
	// finish, before forcefully closing the connection. It's intentionally short and not configurable.
	RequestTimeout = 5 * time.Second

	// ShutdownTimeout is the maximum amount of time to wait for the OAuth callback webhook to
	// finish sending its response to the user's browser, before forcefully closing the connection.
	ShutdownTimeout = time.Second
)

// authCodeFlowMu serializes all OAuth Authorization Code flows, which may start concurrently (e.g., collectors).
// There's no need to stop waiting for it when the context is canceled: initial OAuth flows run before
// the signal handler is installed, so a shutdown signal terminates the process immediately.
var authCodeFlowMu sync.Mutex

// DoInitialOAuthFlow performs the initial OAuth flow based on the configured grant type.
// Afterwards, it clears parsed configuration details and leaves only runtime state management.
//
// The provided context must be long-running and include an [http.Client] value under the
// [oauth2.HTTPClient] key. Calling this function has no effect for non-OAuth configs.
func (c *Config) DoInitialOAuthFlow(ctx context.Context) error {
	if c == nil || c.authType != configTypeOAuth {
		return nil
	}

	defer func() {
		c.oauthConfig = nil
		c.oauthClientCreds = nil
		c.oauthAuthParams = nil
		c.oauthTokenParams = nil
		c.oauthWebhookAddr = ""
		c.oauthRefreshToken = ""

		c.jwtTemplate = nil
		c.jwtSigningKey = nil

		c.oauthState = ""
		c.oauthVerifier = ""
	}()

	switch c.grant {
	case grantTypeAuthCode:
		return c.oauthAuthCodeFlow(ctx)
	case grantTypeClientCreds:
		c.oauthTokenSrc = newSharedTokenSource(c.oauthClientCreds.TokenSource(ctx), nil)
	case grantTypeRefreshToken:
		src := c.oauthConfig.TokenSource(ctx, &oauth2.Token{RefreshToken: c.oauthRefreshToken})
		c.oauthTokenSrc = newSharedTokenSource(src, nil)
	case grantTypeJWTBearer:
		return c.oauthJWTBearerFlow(ctx)
	default:
		return fmt.Errorf("unhandled grant type %q", c.grant)
	}

	if _, err := c.oauthTokenSrc.Token(ctx); err != nil {
		c.oauthTokenSrc = nil
		return fmt.Errorf("OAuth %q flow failed: %w", c.grant, err)
	}
	return nil
}

func (c *Config) oauthAuthCodeFlow(ctx context.Context) error {
	authCodeFlowMu.Lock()
	defer authCodeFlowMu.Unlock()

	c.oauthState = oauth2.GenerateVerifier()

	// Listen before opening the browser, instead of calling [http.Server.ListenAndServe],
	// so callbacks can't arrive before the webhook is ready, and so an unavailable
	// address will fail the flow immediately, instead of after [CallbackTimeout].
	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", c.oauthWebhookAddr)
	if err != nil {
		return fmt.Errorf("failed to listen for OAuth callbacks: %w", err)
	}
	webhook := c.newOAuthWebhook(ctx, c.oauthWebhookAddr)
	defer webhook.shutdown(ctx)
	go func() {
		if err := webhook.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("OAuth callback webhook error", slog.Any("error", err), slog.String("tcp_addr", c.oauthWebhookAddr))
		}
	}()

	url := c.oauthConfig.AuthCodeURL(c.oauthState, c.oauthAuthCodeOpts()...)
	slog.Info("opening browser for OAuth Authorization Code flow: " + url)
	if err := browser.OpenURL(ctx, url); err != nil {
		slog.Warn("failed to start browser", slog.Any("error", err))
		// Don't abort, allow the user to complete the OAuth flow in a browser window that they opened on their own.
	}

	return webhook.wait()
}

// wait waits for the result of the handler that claimed the flow, up to [CallbackTimeout]. Then it tries to claim it
// itself, so later callbacks are rejected. If a handler claimed it just in time, it waits for that handler's result
// instead, which is bounded by [RequestTimeout], so the flow never returns while a handler still uses the [Config].
// It's separate from [Config.oauthAuthCodeFlow] so it can be tested with [testing/synctest], which doesn't advance
// its fake clock while a goroutine (e.g., the webhook) is blocked on network I/O.
func (ow *oauthWebhook) wait() error {
	var ok bool
	select {
	case ok = <-ow.result:
	case <-time.After(CallbackTimeout):
		if ow.tryClaim() {
			return errors.New("authorization code flow timed out")
		}
		ok = <-ow.result
	}

	if !ok {
		return errors.New("authorization code flow failed")
	}
	return nil
}

// shutdown shuts down the webhook gracefully, so the browser receives the callback's response instead
// of a connection error, and forcefully closes the remaining connections after [ShutdownTimeout].
func (ow *oauthWebhook) shutdown(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ShutdownTimeout)
	defer cancel()

	if err := ow.Shutdown(ctx); err != nil {
		_ = ow.Close()
	}
}

// May include [oauth2.AccessTypeOnline] or [oauth2.AccessTypeOffline],
// [oauth2.ApprovalForce], [oauth2.S256ChallengeOption], etc.
func (c *Config) oauthAuthCodeOpts() []oauth2.AuthCodeOption {
	var opts []oauth2.AuthCodeOption
	for k, v := range c.oauthAuthParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	if c.oauthPKCE {
		c.oauthVerifier = oauth2.GenerateVerifier()
		opts = append(opts, oauth2.S256ChallengeOption(c.oauthVerifier))
	}
	return opts
}

func (c *Config) oauthJWTBearerFlow(ctx context.Context) error {
	src := &jwtTokenSource{
		ctx:      ctx,
		tokenURL: c.oauthConfig.Endpoint.TokenURL,
		claims:   maps.Clone(map[string]any(c.jwtTemplate.Claims.(jwt.MapClaims))), //nolint:errcheck // OK by definition.
		method:   c.jwtTemplate.Method,
		exp:      c.jwtExpiration,
		key:      c.jwtSigningKey,
	}
	token, err := src.Token()
	if err != nil {
		return err
	}

	c.oauthTokenSrc = newSharedTokenSource(oauth2.ReuseTokenSource(token, src), token)
	return nil
}

// sharedTokenSource wraps an [oauth2.TokenSource], to share each token request among all its concurrent callers,
// including its error. Without it, an [oauth2.TokenSource] instance would make each caller that waited for a failed
// request send its own request in turn, one at a time, because it holds its lock during each request, and it doesn't
// cache errors. It also lets callers stop waiting when their own context is canceled (e.g., when a client aborts its
// in-flight requests), while the request itself continues in the background, bounded by the context and timeout of
// its own HTTP client, so it doesn't block or leak, and its token is still reusable by other callers.
type sharedTokenSource struct {
	src   oauth2.TokenSource
	token atomic.Pointer[oauth2.Token]
	group singleflight.Group
}

func newSharedTokenSource(src oauth2.TokenSource, t *oauth2.Token) *sharedTokenSource {
	s := &sharedTokenSource{src: src}
	s.token.Store(t)
	return s
}

// Token returns the current token if it's still valid, without any locking. Otherwise, it requests a new one,
// or joins a request that's already in progress, and waits for its result until the given context is canceled.
func (s *sharedTokenSource) Token(ctx context.Context) (*oauth2.Token, error) {
	if t := s.token.Load(); t.Valid() { // Nil-safe, and has the same expiry margin as [oauth2.ReuseTokenSource].
		return t, nil
	}

	ch := s.group.DoChan("", func() (any, error) {
		t, err := s.src.Token()
		if err != nil {
			return nil, err //nolint:wrapcheck // The caller wraps it.
		}
		s.token.Store(t)
		return t, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err() //nolint:wrapcheck // The caller wraps it.
	case result := <-ch:
		if result.Err != nil {
			return nil, result.Err
		}
		return result.Val.(*oauth2.Token), nil //nolint:errcheck,forcetypeassert // OK by definition.
	}
}
