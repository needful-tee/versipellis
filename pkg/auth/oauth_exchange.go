package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// oauthWebhook is a short-lived HTTP server for the redirected callback phase in OAuth Authorization Code flows.
type oauthWebhook struct {
	http.Server

	claimed atomic.Bool
	result  chan bool // Buffered, and receives at most one result: from the handler that claimed the flow.
}

func (c *Config) newOAuthWebhook(ctx context.Context, addr string) *oauthWebhook {
	w := &oauthWebhook{
		Addr:         addr,
		ReadTimeout:  RequestTimeout,
		WriteTimeout: RequestTimeout,
		IdleTimeout:  CallbackTimeout,
		ErrorLog:     slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),

		result: make(chan bool, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", w.exchangeHandler(ctx, c))
	mux.HandleFunc("GET /favicon.ico", http.NotFound)
	w.Handler = mux

	return w
}

// Redirection of the user's original OAuth request from the identity provider back to us, after user
// authentication and authorization. Our response is sent to the browser, not to the OAuth server.
func (ow *oauthWebhook) exchangeHandler(ctx context.Context, cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			slog.Warn("failed to parse OAuth callback request", slog.Any("error", err))
			respondToUser(w, http.StatusBadRequest, "error: The callback is invalid")
			return
		}

		state := r.FormValue("state")
		if state == "" {
			slog.Warn("missing state in OAuth callback request")
			respondToUser(w, http.StatusBadRequest, "error: The callback is invalid")
			return
		}
		if state != cfg.oauthState {
			slog.Warn("incorrect state in OAuth callback request", slog.String("got", state))
			respondToUser(w, http.StatusBadRequest, "error: The callback is invalid")
			return
		}

		// After the state check, to prevent denial-of-service attacks.
		if !ow.tryClaim() {
			slog.Warn("ignoring duplicate or late OAuth callback request")
			respondToUser(w, http.StatusConflict, "error: The flow is already complete")
			return
		}
		if errMsg := r.FormValue("error"); errMsg != "" {
			slog.Warn("OAuth callback returned an error", slog.String("error", errMsg),
				slog.String("description", r.FormValue("error_description")), slog.String("uri", r.FormValue("error_uri")),
			)
			respondToUser(w, http.StatusBadRequest, "failed: The identity provider reported an error")
			ow.result <- false
			return
		}

		code := r.FormValue("code")
		if code == "" {
			slog.Warn("missing code in OAuth callback request")
			respondToUser(w, http.StatusBadRequest, "failed: The identity provider did not return an authorization code")
			ow.result <- false
			return
		}
		opts := make([]oauth2.AuthCodeOption, 0, 1)
		if cfg.oauthVerifier != "" {
			opts = append(opts, oauth2.VerifierOption(cfg.oauthVerifier))
		}

		// Not using the received request's context because it's short-lived and we don't control it. In contrast,
		// the provided flow context is long-running and includes an [http.Client] value for [oauth2.Config.Exchange].
		exchangeCtx, cancel := context.WithTimeout(ctx, requestTimeout(ctx))
		defer cancel()

		token, err := cfg.oauthConfig.Exchange(exchangeCtx, code, opts...)
		if err != nil {
			slog.Warn("failed to exchange OAuth code into token", slog.Any("error", err))
			respondToUser(w, http.StatusBadGateway, "failed: The identity provider did not return an access token")
			ow.result <- false
			return
		}

		// Same as above, the [oauth2.TokenSource] in [newSharedTokenSource] requires a long-lived
		// context that includes an embedded [http.Client] value under the [oauth2.HTTPClient] key.
		cfg.oauthTokenSrc = newSharedTokenSource(cfg.oauthConfig.TokenSource(ctx, token), token)
		respondToUser(w, http.StatusOK, "success: You can close this browser window now")
		ow.result <- true
	}
}

func respondToUser(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "OAuth flow %s.\n", msg)
}

// tryClaim reports whether the caller is the first to claim the flow, so it's the only one that may complete it:
// either the first handler that receives a callback with the correct state, or [oauthWebhook.wait] when it times
// out. So duplicate callbacks (e.g., a reloaded browser page) are rejected instead of exchanging the same code
// again, blocking on the result channel, or modifying the [Config] even after the flow already returned.
func (ow *oauthWebhook) tryClaim() bool {
	return ow.claimed.CompareAndSwap(false, true)
}

type jwtTokenSource struct {
	ctx context.Context //nolint:containedctx // Copied from the Go Team's own [golang.org/x/oauth2/jwt].

	tokenURL string
	method   jwt.SigningMethod
	claims   map[string]any
	exp      time.Duration
	key      any
}

func (j *jwtTokenSource) Token() (*oauth2.Token, error) {
	now := time.Now()
	j.claims["iat"] = now.Unix()
	j.claims["exp"] = now.Add(j.exp).Unix()

	signed, err := jwt.NewWithClaims(j.method, jwt.MapClaims(j.claims)).SignedString(j.key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT with private key: %w", err)
	}

	token, _, err := exchangeJWT(j.ctx, j.tokenURL, signed)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange JWT into OAuth token: %w", err)
	}
	return token, nil
}

// exchangeJWT receives from the caller a signed JWT, and sends it to an OAuth token endpoint in order
// to obtain an OAuth access token, and potentially an OpenID Connect (OIDC) ID token, using the JWT
// bearer flow. This function is an improved version of Config.Token() in [golang.org/x/oauth2/jwt].
func exchangeJWT(ctx context.Context, tokenURL, signedJWT string) (*oauth2.Token, *jwt.Token, error) {
	form := url.Values{}
	form.Set("grant_type", string(grantTypeJWTBearer))
	form.Set("assertion", signedJWT)

	data, status, err := requestTokenWithRetries(ctx, tokenURL, form.Encode())
	if err != nil {
		return nil, nil, err
	}

	parsed := make(map[string]any)
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, nil, fmt.Errorf("received invalid OAuth token: %w", err)
	}

	// OAuth error response (RFC 6749 section 5.2), the same error type as in [golang.org/x/oauth2]'s own grants.
	if errCode := extract[string](parsed, "error"); errCode != "" {
		return nil, nil, &oauth2.RetrieveError{
			ErrorCode:        errCode,
			ErrorDescription: extract[string](parsed, "error_description"),
			ErrorURI:         extract[string](parsed, "error_uri"),
		}
	}
	if status >= http.StatusBadRequest {
		return nil, nil, fmt.Errorf("OAuth token endpoint returned error status %d without details", status)
	}

	// OAuth.
	token := &oauth2.Token{
		AccessToken:  extract[string](parsed, "access_token"),
		TokenType:    extract[string](parsed, "token_type"),
		RefreshToken: extract[string](parsed, "refresh_token"),
		ExpiresIn:    expiresIn(parsed),
		Expiry:       time.Time{},
	}
	if token.AccessToken == "" {
		return nil, nil, errors.New("response from OAuth token endpoint missing an access token")
	}
	if token.ExpiresIn > 0 {
		token.Expiry = time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
	}

	// OIDC (optional).
	id, _, _ := jwt.NewParser().ParseUnverified(extract[string](parsed, "id_token"), jwt.MapClaims{})
	return token.WithExtra(parsed), id, nil
}

const (
	// Simple retry policy for JWT bearer token requests. No need for exponential backoff or jitter because
	// there's no concurrency at this stage. Anyway, even with [RequestTimeout], the worst-case total is
	// still much less than [minJWTExpiration], so all the attempts can reuse the same signed JWT.
	jwtMaxAttempts = 3
	jwtRetryDelay  = time.Second

	// MaxTokenResponseSize is the same limit that [golang.org/x/oauth2] applies to token responses,
	// except that larger responses fail explicitly, instead of being truncated before parsing.
	maxTokenResponseSize = 1 << 20 // 1 MiB.
)

// The context must be long-running and include an [http.Client] value under the [oauth2.HTTPClient] key.
func requestTokenWithRetries(ctx context.Context, tokenURL, form string) ([]byte, int, error) {
	client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok || client == nil {
		client = &http.Client{Timeout: RequestTimeout}
	}

	for attempt := 1; ; attempt++ {
		body, status, err := requestTokenOnce(ctx, client, tokenURL, form)
		if body != nil {
			return body, status, nil
		}
		if !retryable(status) || attempt >= jwtMaxAttempts || ctx.Err() != nil {
			return nil, status, err
		}
		slog.Info("retrying OAuth token request", slog.Any("error", err), slog.Int("attempt", attempt))

		select {
		case <-ctx.Done():
			return nil, http.StatusServiceUnavailable, fmt.Errorf("stopped retrying OAuth token request: %w", ctx.Err())
		case <-time.After(jwtRetryDelay):
			// Continue to the next attempt.
		}
	}
}

// requestTokenOnce sends a single HTTP POST request to the OAuth token endpoint with the given form data.
// It returns the response body (when the status code is 2xx/400/401), HTTP status code, and any error encountered.
func requestTokenOnce(ctx context.Context, client *http.Client, tokenURL, form string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout(ctx))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	var oauthErr error
	if resp.StatusCode >= http.StatusBadRequest {
		oauthErr = errors.New("OAuth token endpoint returned an error: " + resp.Status)
	}
	// OAuth error responses have a 400 or 401 status, and a well-defined body (RFC 6749 section 5.2).
	if resp.StatusCode > http.StatusUnauthorized {
		return nil, resp.StatusCode, oauthErr
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize+1))
	switch {
	case oauthErr != nil && (err != nil || len(body) > maxTokenResponseSize):
		return nil, resp.StatusCode, oauthErr
	case err != nil:
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to read OAuth token response: %w", err)
	case len(body) > maxTokenResponseSize:
		return nil, http.StatusRequestEntityTooLarge, errors.New("OAuth token response is too large")
	}

	return body, resp.StatusCode, nil // 2xx, 400, or 401.
}

// requestTimeout returns the timeout for a single OAuth token request: the timeout of the [http.Client]
// under the context's [oauth2.HTTPClient] key (i.e. the component's timeout), but at most [RequestTimeout].
// Without such a client, or if it has no timeout, the request's default timeout is [RequestTimeout].
func requestTimeout(ctx context.Context) time.Duration {
	if client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && client != nil && client.Timeout > 0 {
		return min(client.Timeout, RequestTimeout)
	}
	return RequestTimeout
}

// Semantically the same as the "retryable" map in http/client.go, but there's no "correct" location
// for a shared definition, and they (generic HTTP vs. OAuth-specific HTTP) may diverge in the future.
func retryable(status int) bool {
	switch status {
	case http.StatusRequestTimeout,
		http.StatusConflict,
		http.StatusPreconditionFailed,
		http.StatusMisdirectedRequest,
		http.StatusLocked,
		http.StatusFailedDependency,
		http.StatusTooEarly,
		http.StatusPreconditionRequired,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		http.StatusInsufficientStorage:
		return true
	// https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#Nonstandard_codes
	case 520, 521, 522, 523, 524, 529, 598, 599:
		return true
	default:
		return false
	}
}

func extract[T any](m map[string]any, key string) T {
	if v, found := m[key]; found {
		if t, ok := v.(T); ok {
			delete(m, key)
			return t
		}
	}
	var zero T
	return zero
}

// This should be a JSON number (according to RFC 6749 section 5.1), but some identity providers send it as a numeric
// string, which [golang.org/x/oauth2] accepts too. Otherwise, the token would never expire (and never be refreshed).
func expiresIn(m map[string]any) int64 {
	if n := extract[float64](m, "expires_in"); n != 0 {
		return int64(n)
	}
	if s, ok := m["expires_in"].(string); ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			delete(m, "expires_in")
			return n
		}
	}
	return 0
}
