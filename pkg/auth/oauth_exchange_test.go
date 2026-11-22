package auth

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"needful-t.ee/versipellis/internal/sandbox"
)

func TestJWTTokenSourceSigningError(t *testing.T) {
	t.Parallel()

	// An ECDSA signing method with an Ed25519 key (any other type would be rejected too).
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	src := &jwtTokenSource{method: jwt.SigningMethodES256, claims: map[string]any{"iss": "issuer"}, exp: time.Minute, key: key}

	if _, err := src.Token(); err == nil {
		t.Error("jwtTokenSource.Token() error = nil, want error")
	}
}

func TestOAuthExchangeHandler(t *testing.T) {
	t.Parallel()

	const (
		state    = "test-state"
		verifier = "test-verifier"
	)

	tests := []struct {
		name         string
		query        url.Values
		rawQuery     string // Overrides query, for unparsable queries.
		pkce         bool
		tokenStatus  int
		tokenBody    string // Overrides the default response body of the token endpoint.
		wantStatus   int
		wantSignal   bool // Whether the handler reports the flow's result.
		wantOK       bool
		wantTokenSrc bool
		wantExchange bool // Whether the handler is expected to call the token endpoint.
		wantRefresh  bool // Whether the token source is expected to refresh the exchanged token.
	}{
		{
			name:       "unparsable_query",
			rawQuery:   "state=%zz",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing_state",
			query:      url.Values{"code": {"c0de"}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "wrong_state_with_error_does_not_abort_the_flow",
			query:      url.Values{"state": {"other"}, "error": {"access_denied"}},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "provider_error",
			query:      url.Values{"state": {state}, "error": {"access_denied"}, "error_description": {"nope"}},
			wantStatus: http.StatusBadRequest,
			wantSignal: true,
		},
		{
			name:       "missing_code",
			query:      url.Values{"state": {state}},
			wantStatus: http.StatusBadRequest,
			wantSignal: true,
		},
		{
			name:         "exchange_failure",
			query:        url.Values{"state": {state}, "code": {"c0de"}},
			tokenStatus:  http.StatusBadRequest,
			wantStatus:   http.StatusBadGateway,
			wantSignal:   true,
			wantExchange: true,
		},
		{
			name:         "success",
			query:        url.Values{"state": {state}, "code": {"c0de"}},
			tokenStatus:  http.StatusOK,
			wantStatus:   http.StatusOK,
			wantSignal:   true,
			wantOK:       true,
			wantTokenSrc: true,
			wantExchange: true,
		},
		{
			name:         "success_with_pkce",
			query:        url.Values{"state": {state}, "code": {"c0de"}},
			pkce:         true,
			tokenStatus:  http.StatusOK,
			wantStatus:   http.StatusOK,
			wantSignal:   true,
			wantOK:       true,
			wantTokenSrc: true,
			wantExchange: true,
		},
		{
			// Expires within the expiry margin of [oauth2.Token.Valid], so the first use refreshes it.
			name:         "expiring_token_is_refreshed",
			query:        url.Values{"state": {state}, "code": {"c0de"}},
			tokenStatus:  http.StatusOK,
			tokenBody:    `{"access_token":"t0k3n","token_type":"Bearer","expires_in":1,"refresh_token":"r3fr3sh"}`,
			wantStatus:   http.StatusOK,
			wantSignal:   true,
			wantOK:       true,
			wantTokenSrc: true,
			wantExchange: true,
			wantRefresh:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := `{"error":"invalid_grant"}`
			if tt.tokenStatus == http.StatusOK {
				body = `{"access_token":"t0k3n","token_type":"Bearer","expires_in":3600}`
			}
			// The token URL is never contacted: only the flow's client can reach the fake endpoint.
			endpoint := &fakeTokenEndpoint{status: tt.tokenStatus, body: cmp.Or(tt.tokenBody, body)}
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: endpoint})

			c := &Config{
				oauthState: state,
				oauthConfig: &oauth2.Config{
					ClientID:     "id",
					ClientSecret: "secret",
					Endpoint:     oauth2.Endpoint{TokenURL: testTokenURL},
				},
			}
			if tt.pkce {
				c.oauthVerifier = verifier
			}

			ow := c.newOAuthWebhook(ctx, testCallbackAddr)
			handler := ow.exchangeHandler(ctx, c)
			target := "/?" + cmp.Or(tt.rawQuery, tt.query.Encode())
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("handler status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if rec.Body.Len() == 0 {
				t.Error("handler response body is empty, want a message for the user")
			}
			select {
			case got := <-ow.result:
				if !tt.wantSignal {
					t.Errorf("handler reported a result (%v), want none", got)
				} else if got != tt.wantOK {
					t.Errorf("handler result = %v, want %v", got, tt.wantOK)
				}
			default:
				if tt.wantSignal {
					t.Error("handler didn't report a result")
				}
			}
			if (c.oauthTokenSrc != nil) != tt.wantTokenSrc {
				t.Errorf("Config.oauthTokenSrc set = %v, want %v", c.oauthTokenSrc != nil, tt.wantTokenSrc)
			}

			// A duplicate callback (e.g., a reloaded browser page) must never complete the flow again, even after the
			// flow returned and cleared its parsed config details, and it must not block: there's no result reader.
			formsBefore, _ := endpoint.requests()
			srcBefore := c.oauthTokenSrc
			c.oauthConfig = nil
			wantDupStatus := tt.wantStatus
			if tt.wantSignal {
				wantDupStatus = http.StatusConflict
			}
			dup := httptest.NewRecorder()
			handler(dup, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
			if dup.Code != wantDupStatus {
				t.Errorf("duplicate callback status = %d, want %d", dup.Code, wantDupStatus)
			}
			formsAfter, _ := endpoint.requests()
			if len(ow.result) > 0 || c.oauthTokenSrc != srcBefore || len(formsAfter) != len(formsBefore) {
				t.Error("duplicate callback reported a result, replaced the token source, or exchanged its code")
			}

			forms, _ := endpoint.requests()
			if (len(forms) > 0) != tt.wantExchange {
				t.Fatalf("token endpoint got %d requests, want any: %v", len(forms), tt.wantExchange)
			}
			if !tt.wantExchange {
				return
			}
			if got := forms[0].Get("code"); got != "c0de" {
				t.Errorf("token request code = %q, want %q", got, "c0de")
			}
			wantVerifier := ""
			if tt.pkce {
				wantVerifier = verifier
			}
			if got := forms[0].Get("code_verifier"); got != wantVerifier {
				t.Errorf("token request code_verifier = %q, want %q", got, wantVerifier)
			}
			if !tt.wantTokenSrc {
				return
			}

			// A valid token must be reused, and an expiring one must be refreshed through the flow's client.
			tok, err := c.oauthTokenSrc.Token(t.Context())
			if err != nil || tok.AccessToken != "t0k3n" {
				t.Errorf("token source Token() = %+v, %v, want an access token", tok, err)
			}
			forms, _ = endpoint.requests()
			wantReqs := 1
			if tt.wantRefresh {
				wantReqs = 2
			}
			if len(forms) != wantReqs {
				t.Fatalf("token endpoint got %d requests, want %d", len(forms), wantReqs)
			}
			if tt.wantRefresh {
				if got := forms[1].Get("refresh_token"); got != "r3fr3sh" {
					t.Errorf("token refresh request refresh_token = %q, want %q", got, "r3fr3sh")
				}
			}
		})
	}
}

// Concurrent duplicate callbacks (e.g., a page reloaded while the code exchange is still in progress) must complete
// the flow exactly once, without blocking. Run with -race: a non-atomic claim is reported as a data race.
func TestOAuthExchangeHandlerConcurrentDuplicates(t *testing.T) {
	t.Parallel()

	const (
		state      = "test-state"
		duplicates = 10
	)

	endpoint := &fakeTokenEndpoint{status: http.StatusOK, body: `{"access_token":"t0k3n","token_type":"Bearer"}`}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: endpoint})
	c := &Config{
		oauthState: state,
		oauthConfig: &oauth2.Config{
			ClientID:     "id",
			ClientSecret: "secret",
			Endpoint:     oauth2.Endpoint{TokenURL: testTokenURL},
		},
	}
	ow := c.newOAuthWebhook(ctx, testCallbackAddr)
	handler := ow.exchangeHandler(ctx, c)
	target := "/?" + url.Values{"state": {state}, "code": {"c0de"}}.Encode()

	// All the handlers are released at once, to maximize their overlap.
	start := make(chan struct{})
	statuses := make(chan int, duplicates)
	var wg sync.WaitGroup
	for range duplicates {
		wg.Go(func() {
			<-start
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
			statuses <- rec.Code
		})
	}
	close(start)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(RequestTimeout):
		t.Fatal("handlers are still blocked, want all of them to return without a result reader")
	}

	close(statuses)
	completed := 0
	for status := range statuses {
		switch status {
		case http.StatusOK:
			completed++
		case http.StatusConflict:
		default:
			t.Errorf("handler status = %d, want %d or %d", status, http.StatusOK, http.StatusConflict)
		}
	}
	if completed != 1 {
		t.Errorf("%d handlers completed the flow, want exactly 1", completed)
	}
	if len(ow.result) != 1 || !<-ow.result {
		t.Error("handlers didn't report exactly one successful result")
	}
	if forms, _ := endpoint.requests(); len(forms) != 1 {
		t.Errorf("token endpoint got %d requests, want the code to be exchanged exactly once", len(forms))
	}
}

func TestExchangeJWT(t *testing.T) {
	t.Parallel()

	// An optional OpenID Connect (OIDC) ID token, which is parsed but not verified.
	idJWT, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user"}).SignedString([]byte("hmac"))
	if err != nil {
		t.Fatalf("jwt.Token.SignedString() error = %v", err)
	}
	okBody := `{"access_token":"t0k3n","token_type":"Bearer","expires_in":3600,"custom":"extra","id_token":"` + idJWT + `"}`
	// Only the default client's case needs a real server, and [httptest.NewServer] panics if it can't listen.
	serverURL := testTokenURL
	if sandbox.CheckLoopback(t) == nil {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, okBody)
		}))
		t.Cleanup(server.Close)
		serverURL = server.URL
	}

	tests := []struct {
		name     string
		tokenURL string
		client   *http.Client // Nil means the default (ephemeral) client, which requires loopback TCP.
		wantErr  bool
		wantCode string // The parsed OAuth error code (RFC 6749 section 5.2), if any.
	}{
		{
			name:     "default_client",
			tokenURL: serverURL,
		},
		{
			name:     "expires_in_as_string",
			tokenURL: testTokenURL,
			client: &http.Client{Transport: &fakeTokenEndpoint{
				status: http.StatusOK, body: strings.Replace(okBody, `"expires_in":3600`, `"expires_in":"3600"`, 1),
			}},
		},
		{
			name:     "invalid_url",
			tokenURL: "https://example.com/\x7f", //gosec:disable G101 // URL, not a credential.
			client:   &http.Client{Transport: failingTransport{}},
			wantErr:  true,
		},
		{
			name:     "oauth_error_with_400_status",
			tokenURL: testTokenURL,
			client: &http.Client{Transport: &fakeTokenEndpoint{
				status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"JWT expired"}`,
			}},
			wantErr:  true,
			wantCode: "invalid_grant",
		},
		{
			name:     "oauth_error_with_401_status",
			tokenURL: testTokenURL,
			client: &http.Client{
				Transport: &fakeTokenEndpoint{status: http.StatusUnauthorized, body: `{"error":"invalid_client"}`},
			},
			wantErr:  true,
			wantCode: "invalid_client",
		},
		{
			name:     "oauth_error_with_200_status",
			tokenURL: testTokenURL,
			client:   &http.Client{Transport: &fakeTokenEndpoint{status: http.StatusOK, body: `{"error":"invalid_scope"}`}},
			wantErr:  true,
			wantCode: "invalid_scope",
		},
		{
			name:     "400_status_without_oauth_error",
			tokenURL: testTokenURL,
			client:   &http.Client{Transport: &fakeTokenEndpoint{status: http.StatusBadRequest, body: "Bad Request"}},
			wantErr:  true,
		},
		{
			name:     "401_status_with_valid_token",
			tokenURL: testTokenURL,
			client:   &http.Client{Transport: &fakeTokenEndpoint{status: http.StatusUnauthorized, body: okBody}},
			wantErr:  true,
		},
		{
			name:     "403_status_with_oauth_error_is_not_parsed",
			tokenURL: testTokenURL,
			client: &http.Client{
				Transport: &fakeTokenEndpoint{status: http.StatusForbidden, body: `{"error":"access_denied"}`},
			},
			wantErr: true,
		},
		{
			name:     "invalid_json_response",
			tokenURL: testTokenURL,
			client:   &http.Client{Transport: &fakeTokenEndpoint{status: http.StatusOK, body: "not json"}},
			wantErr:  true,
		},
		{
			name:     "trailing_data_after_json_response",
			tokenURL: testTokenURL,
			client:   &http.Client{Transport: &fakeTokenEndpoint{status: http.StatusOK, body: okBody + "{}"}},
			wantErr:  true,
		},
		{
			name:     "response_at_size_limit",
			tokenURL: testTokenURL,
			client: &http.Client{
				Transport: &fakeTokenEndpoint{status: http.StatusOK, body: padJSON(okBody, maxTokenResponseSize)},
			},
		},
		{
			name:     "response_over_size_limit",
			tokenURL: testTokenURL,
			client: &http.Client{
				Transport: &fakeTokenEndpoint{status: http.StatusOK, body: padJSON(okBody, maxTokenResponseSize+1)},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tt.client != nil {
				ctx = context.WithValue(ctx, oauth2.HTTPClient, tt.client)
			} else {
				sandbox.RequireLoopback(t)
			}

			token, id, err := exchangeJWT(ctx, tt.tokenURL, "signed.jwt.assertion")
			if (err != nil) != tt.wantErr {
				t.Fatalf("exchangeJWT() error = %v, wantErr %v", err, tt.wantErr)
			}
			if retrieveErr, ok := errors.AsType[*oauth2.RetrieveError](err); ok != (tt.wantCode != "") {
				t.Errorf("exchangeJWT() error = %v, want an OAuth error response: %v", err, tt.wantCode != "")
			} else if ok && retrieveErr.ErrorCode != tt.wantCode {
				t.Errorf("exchangeJWT() OAuth error code = %q, want %q", retrieveErr.ErrorCode, tt.wantCode)
			}
			if tt.wantErr {
				if token != nil || id != nil {
					t.Errorf("exchangeJWT() = %+v, %+v, want nil tokens", token, id)
				}
				return
			}

			if token.AccessToken != "t0k3n" || token.TokenType != "Bearer" || token.ExpiresIn != 3600 {
				t.Errorf("exchangeJWT() token = %+v, want the token from the response", token)
			}
			if remaining := time.Until(token.Expiry); remaining <= 59*time.Minute || remaining > time.Hour {
				t.Errorf("exchangeJWT() token expires in %v, want about 1 hour", remaining)
			}
			if got := token.Extra("custom"); got != "extra" {
				t.Errorf("exchangeJWT() token extra field = %v, want %q", got, "extra")
			}
			if id == nil {
				t.Fatal("exchangeJWT() ID token = nil, want the parsed OIDC ID token")
			}
			if sub, err := id.Claims.GetSubject(); err != nil || sub != "user" {
				t.Errorf("exchangeJWT() ID token subject = %q, %v, want %q", sub, err, "user")
			}
		})
	}
}

// padJSON appends trailing whitespace to a JSON payload, so it's still valid but has exactly the given size.
func padJSON(payload string, size int) string {
	return payload + strings.Repeat(" ", size-len(payload))
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused by the test")
}

func TestExchangeJWTRetries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		steps        []int
		ctxTimeout   time.Duration
		wantErr      bool
		wantRequests int
		wantElapsed  time.Duration // Total fake time spent waiting between attempts.
	}{
		{
			name:         "success_without_retries",
			steps:        []int{http.StatusOK},
			wantRequests: 1,
		},
		{
			name:         "server_error_then_success",
			steps:        []int{http.StatusServiceUnavailable, http.StatusOK},
			wantRequests: 2,
			wantElapsed:  jwtRetryDelay,
		},
		{
			name:         "nonstandard_server_error_then_success",
			steps:        []int{524, http.StatusOK}, // Cloudflare's "A Timeout Occurred".
			wantRequests: 2,
			wantElapsed:  jwtRetryDelay,
		},
		{
			name:         "network_error_then_success",
			steps:        []int{stepNetworkError, http.StatusOK},
			wantRequests: 2,
			wantElapsed:  jwtRetryDelay,
		},
		{
			name:         "unreadable_body_then_success",
			steps:        []int{stepUnreadableBody, http.StatusOK},
			wantRequests: 2,
			wantElapsed:  jwtRetryDelay,
		},
		{
			name:         "throttled_until_attempts_exhausted",
			steps:        []int{http.StatusTooManyRequests},
			wantErr:      true,
			wantRequests: jwtMaxAttempts,
			wantElapsed:  (jwtMaxAttempts - 1) * jwtRetryDelay, // No delay after the last attempt.
		},
		{
			name:         "oauth_error_is_not_retried",
			steps:        []int{http.StatusBadRequest},
			wantErr:      true,
			wantRequests: 1,
		},
		{
			name:         "unreadable_oauth_error_is_not_retried",
			steps:        []int{-http.StatusBadRequest},
			wantErr:      true,
			wantRequests: 1,
		},
		{
			name:         "not_implemented_is_not_retried",
			steps:        []int{http.StatusNotImplemented},
			wantErr:      true,
			wantRequests: 1,
		},
		{
			name:         "context_canceled_during_backoff",
			steps:        []int{http.StatusServiceUnavailable},
			ctxTimeout:   500 * time.Millisecond,
			wantErr:      true,
			wantRequests: 1,
			wantElapsed:  500 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				tr := &scriptedTransport{steps: tt.steps}
				ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: tr})
				if tt.ctxTimeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
					defer cancel()
				}

				start := time.Now()
				token, _, err := exchangeJWT(ctx, testTokenURL, "signed.jwt.assertion")
				elapsed := time.Since(start)

				if (err != nil) != tt.wantErr {
					t.Errorf("exchangeJWT() error = %v, wantErr %v", err, tt.wantErr)
				}
				if !tt.wantErr && (token == nil || token.AccessToken == "") {
					t.Errorf("exchangeJWT() token = %+v, want an access token", token)
				}
				if got := tr.requests(); got != tt.wantRequests {
					t.Errorf("token endpoint got %d requests, want %d", got, tt.wantRequests)
				}
				if elapsed != tt.wantElapsed {
					t.Errorf("exchangeJWT() returned after %v, want %v", elapsed, tt.wantElapsed)
				}
			})
		})
	}
}

// scriptedTransport is an [http.RoundTripper] that responds to each request with the next step of its script,
// and repeats the last step afterwards, without any network I/O (so it works in [synctest] bubbles).
type scriptedTransport struct {
	steps []int // HTTP status codes, or one of the special steps below.

	mu    sync.Mutex
	calls int
}

// Special steps of [scriptedTransport], instead of HTTP status codes.
const (
	stepNetworkError = 0 // Fails to send the request.

	// Negative steps respond with the corresponding (positive) status, but with a body
	// that fails to be read (e.g., a reset connection), so -[http.StatusOK] is a 200 status.
	stepUnreadableBody = -http.StatusOK
)

func (s *scriptedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	status := s.steps[min(s.calls, len(s.steps)-1)]
	s.calls++
	s.mu.Unlock()

	switch {
	case status == stepNetworkError:
		return nil, errors.New("connection refused by the test")
	case status < 0:
		body := io.NopCloser(iotest.ErrReader(errors.New("connection reset by the test")))
		return &http.Response{StatusCode: -status, Status: http.StatusText(-status), Body: body, Request: r}, nil
	}
	body := `{"error":"temporarily_unavailable"}`
	if status == http.StatusOK {
		body = `{"access_token":"t0k3n","token_type":"Bearer","expires_in":3600}`
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

func (s *scriptedTransport) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestRequestTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		client any // Nil means no context value.
		want   time.Duration
	}{
		{"no_client", nil, RequestTimeout},
		{"nil_client", (*http.Client)(nil), RequestTimeout},
		{"client_without_timeout", &http.Client{}, RequestTimeout},
		{"shorter_client_timeout", &http.Client{Timeout: time.Second}, time.Second},
		{"longer_client_timeout", &http.Client{Timeout: time.Minute}, RequestTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			if tt.client != nil {
				ctx = context.WithValue(ctx, oauth2.HTTPClient, tt.client)
			}
			if got := requestTimeout(ctx); got != tt.want {
				t.Errorf("requestTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}
