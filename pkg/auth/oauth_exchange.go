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
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"uuid"

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
		WriteTimeout: RequestTimeout + ShutdownTimeout, // Respond to the browser even when the exchange is slow/stalled.
		IdleTimeout:  RequestTimeout,
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
	expectedState := cfg.oauthState
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
		if state != expectedState {
			slog.Warn("incorrect state in OAuth callback request")
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
		exchangeCtx, cancel := context.WithTimeout(ctx, RequestTimeout)
		defer cancel()

		token, err := cfg.oauthConfig.Exchange(exchangeCtx, code, opts...)
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
				status = http.StatusGatewayTimeout
			}
			slog.Warn("failed to exchange OAuth code into token", slog.Any("error", err))
			respondToUser(w, status, "failed: The identity provider did not return an access token")
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

const (
	// Simple retry policy for JWT bearer token requests. No need for exponential
	// backoff or jitter because there's no concurrency at this stage.
	jwtMaxAttempts = 3
	jwtRetryDelay  = time.Second

	// MaxTokenResponseSize is the same limit that [golang.org/x/oauth2] applies to token responses,
	// except that larger responses fail explicitly, instead of being truncated before parsing.
	maxTokenResponseSize = 1 << 20 // 1 MiB.
)

type jwtTokenSource struct {
	ctx context.Context //nolint:containedctx // Copied from the Go Team's own [golang.org/x/oauth2/jwt].

	tokenURL     string
	clientID     string
	clientSecret string
	authStyle    oauth2.AuthStyle

	method jwt.SigningMethod
	claims map[string]any
	exp    time.Duration
	key    any
}

func (j *jwtTokenSource) Token() (*oauth2.Token, error) {
	switch {
	case j.authStyle != oauth2.AuthStyleAutoDetect:
		// Already initialized, skip this switch block.
	case j.clientID == "" || j.clientSecret == "":
		j.authStyle = -1 // Never send client credentials at all.
	default:
		j.authStyle = oauth2.AuthStyleInHeader // The first choice of [oauth2.AuthStyleAutoDetect].
	}

	client, ok := j.ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok || client == nil { // Programming error, should never happen normally for users.
		return nil, errors.New("HTTP client not found in context for JWT exchange")
	}
	token, _, err := j.exchangeJWT(client)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange JWT into OAuth token: %w", err)
	}

	return token, nil
}

// exchangeJWT sends to an OAuth token endpoint a POST request which contains (at least) a signed JWT,
// in order to obtain an OAuth access token, and potentially an OpenID Connect (OIDC) ID token.
func (j *jwtTokenSource) exchangeJWT(client *http.Client) (*oauth2.Token, *jwt.Token, error) {
	var body []byte
	var status int
	var err error
	for retry := 1; ; retry++ {
		body, status, err = j.requestToken(client)
		if body != nil {
			break
		}
		if !retryable(status) || retry == jwtMaxAttempts {
			return nil, nil, err
		}
		slog.Info("retrying OAuth token request", slog.Any("error", err),
			slog.Int("status", status), slog.Int("retry", retry),
		)
		select {
		case <-j.ctx.Done():
			return nil, nil, fmt.Errorf("stopped retrying OAuth token request: %w", j.ctx.Err())
		case <-time.After(jwtRetryDelay):
			// Continue to the next attempt.
		}
	}

	parsed := make(map[string]any)
	if err := json.Unmarshal(body, &parsed); err != nil {
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

// requestToken sends a single HTTP POST request and returns the response body when the status code is 2xx/400/401,
// and either way also the HTTP status code and any error encountered. It generates and signs a new JWT assertion
// for each request because the "jti" (JWT ID) claim has to be unique every time (especially in retries).
func (j *jwtTokenSource) requestToken(client *http.Client) ([]byte, int, error) {
	form, err := j.generateJWT()
	if err != nil {
		return nil, 0, err
	}

	ctx, cancel := context.WithTimeout(j.ctx, RequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.tokenURL, form)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if j.authStyle == oauth2.AuthStyleInHeader {
		// Form-URL-encode first, per RFC 6749 section 2.3.1.
		req.SetBasicAuth(url.QueryEscape(j.clientID), url.QueryEscape(j.clientSecret))
	}

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

func (j *jwtTokenSource) generateJWT() (io.Reader, error) {
	now := time.Now()
	j.claims["iat"] = now.Unix()
	j.claims["exp"] = now.Add(j.exp).Unix()
	j.claims["jti"] = uuid.NewV4().String()

	signed, err := jwt.NewWithClaims(j.method, jwt.MapClaims(j.claims)).SignedString(j.key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT with private key: %w", err)
	}

	form := make(url.Values)
	form.Set("grant_type", string(grantTypeJWTBearer))
	form.Set("assertion", signed)
	if scope, ok := j.claims["scope"].(string); ok {
		form.Set("scope", scope)
	}
	if j.clientID != "" {
		form.Set("client_id", j.clientID)
	}
	// Reminder: add a one-time probe, like in [oauth2.Config.Exchange], to enable this auth style.
	if j.authStyle == oauth2.AuthStyleInParams {
		form.Set("client_secret", j.clientSecret)
	}

	return strings.NewReader(form.Encode()), nil
}

// The same as retryable() in http/client.go, but generic HTTP and OAuth-specific policies may diverge in the future.
func retryable(status int) bool {
	switch status {
	// Allow-list of retryable 4xx codes.
	case http.StatusRequestTimeout,
		http.StatusConflict,
		http.StatusLocked,
		http.StatusTooEarly,
		http.StatusTooManyRequests:
		return true
	// Deny-list of non-retryable 5xx codes.
	case http.StatusNotImplemented,
		http.StatusHTTPVersionNotSupported,
		http.StatusVariantAlsoNegotiates,
		http.StatusLoopDetected,
		http.StatusNotExtended,
		http.StatusNetworkAuthenticationRequired,
		525, 526: // https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#Nonstandard_codes
		return false
	// Besides all the above, 5xx codes should be retryable by default, but 2xx-4xx shouldn't be.
	default:
		return status >= http.StatusInternalServerError && status < 600
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
