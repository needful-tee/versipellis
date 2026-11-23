package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"needful-t.ee/versipellis/internal/browser"
	"needful-t.ee/versipellis/internal/sandbox"
)

// fakeTokenEndpoint is an [http.RoundTripper] that responds to every request with a fixed
// token endpoint response, and records the received requests, without any network I/O.
type fakeTokenEndpoint struct {
	status int
	body   string

	mu    sync.Mutex
	forms []url.Values
	auths []string
}

func (f *fakeTokenEndpoint) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err //nolint:wrapcheck // Test helper.
	}

	f.mu.Lock()
	f.forms = append(f.forms, r.PostForm)
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	f.mu.Unlock()

	return &http.Response{
		StatusCode: f.status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Request:    r,
	}, nil
}

func (f *fakeTokenEndpoint) requests() ([]url.Values, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.forms, f.auths
}

func TestConfigDoInitialOAuthFlow(t *testing.T) {
	t.Parallel()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	ecFile := filepath.Join(t.TempDir(), "ec.pem")
	writeTestPEM(t, ecFile, "PRIVATE KEY", der)

	clientCreds := map[string]any{
		"type":                "oauth",
		"oauth_client_id":     "id",
		"oauth_client_secret": "secret",
		"oauth_scopes":        "read write",
		"oauth_token_url":     testTokenURL,
	}
	okBody := `{"access_token":"t0k3n","token_type":"Bearer","expires_in":3600}`
	jwtBearerForm := url.Values{"grant_type": {string(grantTypeJWTBearer)}, "assertion": {"signed JWT"}}
	basicAuth := "Basic aWQ6c2VjcmV0" // "id:secret".

	tests := []struct {
		name       string
		cfg        map[string]any
		status     int
		body       string
		wantForms  []url.Values // One per token request.
		wantAuths  []string     // One per token request.
		wantHeader string
		wantErr    bool
	}{
		{
			name: "none_is_a_no_op",
			cfg:  map[string]any{"type": "none"},
		},
		{
			name:       "static_is_a_no_op",
			cfg:        map[string]any{"type": "static", "static_secret": "s3cr3t"},
			wantHeader: "Bearer s3cr3t",
		},
		{
			name:       "client_credentials",
			cfg:        clientCreds,
			status:     http.StatusOK,
			body:       okBody,
			wantForms:  []url.Values{{"grant_type": {"client_credentials"}, "scope": {"read write"}}},
			wantAuths:  []string{basicAuth},
			wantHeader: "Bearer t0k3n",
		},
		{
			name: "client_credentials_with_token_params",
			cfg: map[string]any{
				"type":                "oauth",
				"oauth_client_id":     "id",
				"oauth_client_secret": "secret",
				"oauth_token_url":     testTokenURL,
				"oauth_token_params":  map[string]any{"audience": "api"},
			},
			status:     http.StatusOK,
			body:       okBody,
			wantForms:  []url.Values{{"grant_type": {"client_credentials"}, "audience": {"api"}}},
			wantAuths:  []string{basicAuth},
			wantHeader: "Bearer t0k3n",
		},
		{
			name: "refresh_token",
			cfg: map[string]any{
				"type":                "oauth",
				"oauth_client_id":     "id",
				"oauth_client_secret": "secret",
				"oauth_refresh_token": "refresh",
				"oauth_token_url":     testTokenURL,
			},
			status:     http.StatusOK,
			body:       okBody,
			wantForms:  []url.Values{{"grant_type": {"refresh_token"}, "refresh_token": {"refresh"}}},
			wantAuths:  []string{basicAuth},
			wantHeader: "Bearer t0k3n",
		},
		{
			name:   "client_credentials_rejected",
			cfg:    clientCreds,
			status: http.StatusUnauthorized,
			body:   `{"error":"invalid_client"}`,
			// With the default [oauth2.AuthStyleAutoDetect], after the first failure, oauth2
			// tries again with the client credentials in the form, instead of the header.
			wantForms: []url.Values{
				{"grant_type": {"client_credentials"}, "scope": {"read write"}},
				{"grant_type": {"client_credentials"}, "scope": {"read write"}, "client_id": {"id"}, "client_secret": {"secret"}},
			},
			wantAuths: []string{basicAuth, ""},
			wantErr:   true,
		},
		{
			name: "jwt_bearer",
			cfg: map[string]any{
				"type":                 "oauth",
				"oauth_token_url":      testTokenURL,
				"jwt_private_key_file": ecFile,
				"jwt_claims": map[string]any{
					"iss": "issuer",
					"sub": "subject",
					"aud": "audience",
					"nbf": int64(1e9),
				}, // Signable integer claim.
			},
			status:     http.StatusOK,
			body:       okBody,
			wantForms:  []url.Values{jwtBearerForm},
			wantAuths:  []string{""},
			wantHeader: "Bearer t0k3n",
		},
		{
			name: "jwt_bearer_with_client_credentials_in_header",
			cfg: map[string]any{
				"type":                 "oauth",
				"oauth_client_id":      "id",
				"oauth_client_secret":  "secret",
				"oauth_scopes":         "read write",
				"oauth_token_url":      testTokenURL,
				"jwt_private_key_file": ecFile,
				"jwt_claims":           map[string]any{"iss": "issuer", "sub": "subject", "aud": "audience"},
			},
			status: http.StatusOK,
			body:   okBody,
			wantForms: []url.Values{
				{
					"grant_type": {string(grantTypeJWTBearer)},
					"assertion":  {"signed JWT"},
					"client_id":  {"id"},
					"scope":      {"read write"},
				},
			},
			wantAuths:  []string{basicAuth},
			wantHeader: "Bearer t0k3n",
		},
		{
			// RFC 6749 section 2.3.1 requires encoding the credentials as form values before using them in the header.
			name: "jwt_bearer_with_special_characters_in_client_credentials",
			cfg: map[string]any{
				"type":                 "oauth",
				"oauth_client_id":      "my id",
				"oauth_client_secret":  "s&cr+t%",
				"oauth_token_url":      testTokenURL,
				"jwt_private_key_file": ecFile,
				"jwt_claims":           map[string]any{"iss": "issuer", "sub": "subject", "aud": "audience"},
			},
			status: http.StatusOK,
			body:   okBody,
			wantForms: []url.Values{
				{"grant_type": {string(grantTypeJWTBearer)}, "assertion": {"signed JWT"}, "client_id": {"my id"}},
			},
			wantAuths:  []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("my+id:s%26cr%2Bt%25"))},
			wantHeader: "Bearer t0k3n",
		},
		{
			// The encoding of the credentials makes it safe to use a colon in the client ID, despite RFC 7617.
			name: "jwt_bearer_with_colon_in_client_id",
			cfg: map[string]any{
				"type":                 "oauth",
				"oauth_client_id":      "a:b",
				"oauth_client_secret":  "secret",
				"oauth_token_url":      testTokenURL,
				"jwt_private_key_file": ecFile,
				"jwt_claims":           map[string]any{"iss": "issuer", "sub": "subject", "aud": "audience"},
			},
			status: http.StatusOK,
			body:   okBody,
			wantForms: []url.Values{
				{"grant_type": {string(grantTypeJWTBearer)}, "assertion": {"signed JWT"}, "client_id": {"a:b"}},
			},
			wantAuths:  []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("a%3Ab:secret"))},
			wantHeader: "Bearer t0k3n",
		},
		{
			name: "jwt_bearer_with_client_id_only_identifies_a_public_client",
			cfg: map[string]any{
				"type":                 "oauth",
				"oauth_client_id":      "id",
				"oauth_token_url":      testTokenURL,
				"jwt_private_key_file": ecFile,
				"jwt_claims":           map[string]any{"iss": "issuer", "sub": "subject", "aud": "audience"},
			},
			status: http.StatusOK,
			body:   okBody,
			wantForms: []url.Values{
				{"grant_type": {string(grantTypeJWTBearer)}, "assertion": {"signed JWT"}, "client_id": {"id"}},
			},
			wantAuths:  []string{""},
			wantHeader: "Bearer t0k3n",
		},
		{
			name: "jwt_bearer_with_scopes",
			cfg: map[string]any{
				"type":                 "oauth",
				"oauth_scopes":         "read write",
				"oauth_token_url":      testTokenURL,
				"jwt_private_key_file": ecFile,
				"jwt_claims":           map[string]any{"iss": "issuer", "sub": "subject", "aud": "audience"},
			},
			status: http.StatusOK,
			body:   okBody,
			wantForms: []url.Values{
				{"grant_type": {string(grantTypeJWTBearer)}, "assertion": {"signed JWT"}, "scope": {"read write"}},
			},
			wantAuths:  []string{""},
			wantHeader: "Bearer t0k3n",
		},
		{
			name: "jwt_bearer_rejected",
			cfg: map[string]any{
				"type":                 "oauth",
				"oauth_token_url":      testTokenURL,
				"jwt_private_key_file": ecFile,
				"jwt_claims":           map[string]any{"iss": "issuer", "sub": "subject", "aud": "audience"},
			},
			status:    http.StatusBadRequest,
			body:      `{"error":"invalid_grant"}`,
			wantForms: []url.Values{jwtBearerForm},
			wantAuths: []string{""},
			wantErr:   true,
		},
		{
			name: "jwt_bearer_without_access_token",
			cfg: map[string]any{
				"type":                 "oauth",
				"oauth_token_url":      testTokenURL,
				"jwt_private_key_file": ecFile,
				"jwt_claims":           map[string]any{"iss": "issuer", "sub": "subject", "aud": "audience"},
			},
			status:    http.StatusOK,
			body:      `{"token_type":"Bearer"}`,
			wantForms: []url.Values{jwtBearerForm},
			wantAuths: []string{""},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := ParseConfig(tt.cfg, &url.URL{Scheme: "https", Host: "example.com"}, tt.name)
			if err != nil {
				t.Fatalf("ParseConfig() error = %v", err)
			}

			endpoint := &fakeTokenEndpoint{status: tt.status, body: tt.body}
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: endpoint})

			if err := c.DoInitialOAuthFlow(ctx); (err != nil) != tt.wantErr {
				t.Fatalf("Config.DoInitialOAuthFlow() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Sensitive parsed configuration details are cleared after the flow, regardless of its result.
			if c.oauthConfig != nil || c.oauthClientCreds != nil ||
				c.oauthRefreshToken != "" || c.jwtTemplate != nil || c.jwtSigningKey != nil {
				t.Errorf("Config.DoInitialOAuthFlow() didn't clear parsed config details: %+v", c)
			}

			// The token must be reused, instead of requesting a new one for each header. After
			// a failed flow, there must be no token source that would keep requesting tokens.
			for range 2 {
				h, err := c.SetHeader(t.Context(), nil, tt.name)
				if err != nil {
					t.Fatalf("Config.SetHeader() error = %v", err)
				}
				if got := h.Get("Authorization"); got != tt.wantHeader {
					t.Errorf("Config.SetHeader() Authorization = %q, want %q", got, tt.wantHeader)
				}
			}

			forms, auths := endpoint.requests()
			if len(forms) != len(tt.wantForms) {
				t.Fatalf("token endpoint got %d requests, want %d", len(forms), len(tt.wantForms))
			}
			for i, form := range forms {
				if assertion := form.Get("assertion"); assertion != "" {
					// The signed JWT differs per request, so verify it and replace it with a placeholder.
					claims := jwt.MapClaims{}
					if _, err := jwt.ParseWithClaims(assertion, claims, func(*jwt.Token) (any, error) {
						return ecKey.Public(), nil
					}, jwt.WithValidMethods([]string{"ES256"})); err != nil {
						t.Errorf("token request %d has an invalid JWT assertion: %v", i+1, err)
					}
					for claim, want := range map[string]string{"iss": "issuer", "sub": "subject", "aud": "audience"} {
						if claims[claim] != want {
							t.Errorf("token request %d JWT %s claim = %v, want %q", i+1, claim, claims[claim], want)
						}
					}
					// Each token has a unique ID, and a lifetime that matches the default expiration.
					if jti, _ := claims["jti"].(string); jti == "" {
						t.Errorf("token request %d JWT jti claim = %v, want a unique ID", i+1, claims["jti"])
					}
					iat, _ := claims.GetIssuedAt()
					exp, _ := claims.GetExpirationTime()
					if iat == nil || exp == nil || exp.Sub(iat.Time) != defaultJWTExpiration {
						t.Errorf(
							"token request %d JWT iat = %v and exp = %v, want a %v lifetime",
							i+1,
							iat,
							exp,
							defaultJWTExpiration,
						)
					}
					form.Set("assertion", "signed JWT")
				}
				if got, want := form.Encode(), tt.wantForms[i].Encode(); got != want {
					t.Errorf("token request %d form = %q, want %q", i+1, got, want)
				}
				if auths[i] != tt.wantAuths[i] {
					t.Errorf("token request %d Authorization = %q, want %q", i+1, auths[i], tt.wantAuths[i])
				}
			}
		})
	}
}

func TestConfigDoInitialOAuthFlowWithUnhandledGrant(t *testing.T) {
	t.Parallel()

	c := &Config{authType: configTypeOAuth, grant: "custom"}
	if err := c.DoInitialOAuthFlow(t.Context()); err == nil {
		t.Error("Config.DoInitialOAuthFlow() error = nil, want error")
	}
}

func TestConfigOAuthAuthCodeOpts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pkce bool
	}{
		{name: "without_pkce"},
		{name: "with_pkce", pkce: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := ParseConfig(map[string]any{
				"type":                   "oauth",
				"oauth_client_id":        "id",
				"oauth_client_secret":    "secret",
				"oauth_pkce":             tt.pkce,
				"oauth_scopes":           "read write",
				"oauth_auth_url":         testAuthURL,
				"oauth_callback_url":     testCallbackURL,
				"oauth_callback_address": testCallbackAddr,
				"oauth_token_url":        testTokenURL,
				"oauth_auth_params":      map[string]any{"access_type": "offline"},
			}, &url.URL{Scheme: "https", Host: "example.com"}, tt.name)
			if err != nil {
				t.Fatalf("ParseConfig() error = %v", err)
			}

			const state = "test-state"
			u, err := url.Parse(c.oauthConfig.AuthCodeURL(state, c.oauthAuthCodeOpts()...))
			if err != nil {
				t.Fatalf("url.Parse(oauth2.Config.AuthCodeURL()) error = %v", err)
			}
			if (c.oauthVerifier != "") != tt.pkce {
				t.Errorf("Config.oauthVerifier = %q, want non-empty: %v", c.oauthVerifier, tt.pkce)
			}

			want := url.Values{
				"access_type":   {"offline"},
				"client_id":     {"id"},
				"redirect_uri":  {testCallbackURL},
				"response_type": {"code"},
				"scope":         {"read write"},
				"state":         {state},
			}
			if tt.pkce {
				want.Set("code_challenge", oauth2.S256ChallengeFromVerifier(c.oauthVerifier))
				want.Set("code_challenge_method", "S256")
			}
			if got := u.Scheme + "://" + u.Host + u.Path; got != testAuthURL {
				t.Errorf("auth code URL base = %q, want %q", got, testAuthURL)
			}
			if got := u.Query().Encode(); got != want.Encode() {
				t.Errorf("auth code URL query = %q, want %q", got, want.Encode())
			}
		})
	}
}

// blockingTokenSource counts its token requests, and blocks each one until its release channel is closed.
type blockingTokenSource struct {
	release chan struct{}
	token   *oauth2.Token
	err     error
	calls   atomic.Int32
}

func (b *blockingTokenSource) Token() (*oauth2.Token, error) {
	b.calls.Add(1)
	<-b.release
	return b.token, b.err
}

func newBlockingTokenSource(token *oauth2.Token, err error, released bool) *blockingTokenSource {
	b := &blockingTokenSource{release: make(chan struct{}), token: token, err: err}
	if released {
		close(b.release)
	}
	return b
}

func TestSharedTokenSourceReuse(t *testing.T) {
	t.Parallel()

	valid := &oauth2.Token{AccessToken: "valid", Expiry: time.Now().Add(time.Hour)}
	expired := &oauth2.Token{AccessToken: "expired", Expiry: time.Now().Add(-time.Hour)}
	fresh := &oauth2.Token{AccessToken: "fresh", Expiry: time.Now().Add(time.Hour)}

	tests := []struct {
		name      string
		initial   *oauth2.Token
		wantToken string
		wantCalls int32
	}{
		{"no_initial_token", nil, "fresh", 1},
		{"valid_initial_token", valid, "valid", 0},
		{"expired_initial_token", expired, "fresh", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			src := newBlockingTokenSource(fresh, nil, true)
			s := newSharedTokenSource(src, tt.initial)
			for range 3 { // A valid token must be reused, instead of requesting a new one each time.
				got, err := s.Token(t.Context())
				if err != nil {
					t.Fatalf("sharedTokenSource.Token() error = %v", err)
				}
				if got.AccessToken != tt.wantToken {
					t.Errorf("sharedTokenSource.Token() = %q, want %q", got.AccessToken, tt.wantToken)
				}
			}
			if got := src.calls.Load(); got != tt.wantCalls {
				t.Errorf("token requests = %d, want %d", got, tt.wantCalls)
			}
		})
	}
}

// Concurrent callers must share a single token request, including its error, instead of
// sending their own requests in turn, one at a time (like [oauth2.ReuseTokenSource] does).
// Note that callers waiting for a [sync.Mutex] aren't durably blocked, so if they serialize
// again, this test fails by hanging in [synctest.Wait] until the "go test" timeout.
func TestSharedTokenSourceConcurrentFailure(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		src := newBlockingTokenSource(nil, errors.New("token endpoint unavailable"), false)
		s := newSharedTokenSource(src, nil)

		const callers = 10
		var wg sync.WaitGroup
		var failures atomic.Int32
		for range callers {
			wg.Go(func() {
				if _, err := s.Token(t.Context()); err != nil {
					failures.Add(1)
				}
			})
		}

		synctest.Wait() // All the callers are waiting for the same request.
		close(src.release)
		wg.Wait()

		if got := src.calls.Load(); got != 1 {
			t.Errorf("token requests = %d, want 1", got)
		}
		if got := failures.Load(); got != callers {
			t.Errorf("sharedTokenSource.Token() failures = %d, want %d", got, callers)
		}
	})
}

// Callers must be able to stop waiting for a token request, which then continues in
// the background, so its token is still reusable afterwards, without another request.
func TestSharedTokenSourceCanceledWait(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		src := newBlockingTokenSource(&oauth2.Token{AccessToken: "t0k3n", Expiry: time.Now().Add(time.Hour)}, nil, false)
		s := newSharedTokenSource(src, nil)

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error)
		go func() {
			_, err := s.Token(ctx)
			done <- err
		}()

		synctest.Wait() // The caller is waiting for the token request.
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("sharedTokenSource.Token() error = %v, want %v", err, context.Canceled)
		}

		close(src.release)
		synctest.Wait() // The abandoned token request completes in the background.

		got, err := s.Token(t.Context())
		if err != nil {
			t.Fatalf("sharedTokenSource.Token() error = %v", err)
		}
		if got.AccessToken != "t0k3n" {
			t.Errorf("sharedTokenSource.Token() = %q, want %q", got.AccessToken, "t0k3n")
		}
		if got := src.calls.Load(); got != 1 {
			t.Errorf("token requests = %d, want 1", got)
		}
	})
}

// freeLoopbackAddr returns a currently unused local TCP address, for an OAuth callback webhook.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()

	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenConfig.Listen() error = %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("net.Listener.Close() error = %v", err)
	}
	return addr
}

// fakeUserAgent returns a [browser.Opener] that acts as both the user and the OAuth provider's authorization
// endpoint: it records the authorization request, and redirects to its callback URL with the given query
// parameters and the request's state, like a provider does after the user approves or denies access.
// It sends the callback's response (what the user sees) to the given channel, and returns openErr afterwards,
// to simulate a browser that failed to start while the user completed the flow on their own.
func fakeUserAgent(
	t *testing.T, callback url.Values, openErr error, authReq chan<- url.Values, callbackResp chan<- callbackResponse,
) browser.Opener {
	t.Helper()

	return func(ctx context.Context, rawURL string) error {
		u, err := url.Parse(rawURL)
		if err != nil {
			t.Errorf("Opener URL %q parsing error = %v", rawURL, err)
			return openErr
		}
		q := u.Query()
		authReq <- q

		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			t.Errorf("redirect_uri %q parsing error = %v", q.Get("redirect_uri"), err)
			return openErr
		}
		params := url.Values{"state": {q.Get("state")}}
		maps.Copy(params, callback)
		redirect.RawQuery = params.Encode()

		// Like a real browser, the callback request is asynchronous, i.e. it isn't done when this function returns,
		// so the flow may shut down the webhook while the response is still in flight (it's a narrow race window,
		// so this isn't a deterministic regression test for that). No retries: the webhook must already be listening
		// when the browser opens.
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, redirect.String(), http.NoBody)
			if err != nil {
				callbackResp <- callbackResponse{err: err}
				return
			}
			client := &http.Client{Timeout: RequestTimeout}
			resp, err := client.Do(req)
			if err != nil {
				callbackResp <- callbackResponse{err: err}
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			callbackResp <- callbackResponse{status: resp.StatusCode, body: string(body), err: err}
		}()
		return openErr
	}
}

// callbackResponse is the OAuth callback webhook's response to the browser, as received by [fakeUserAgent].
type callbackResponse struct {
	status int
	body   string
	err    error
}

func TestConfigDoInitialOAuthFlowAuthorizationCode(t *testing.T) {
	t.Parallel()
	sandbox.RequireLoopback(t)

	const okBody = `{"access_token":"t0k3n","token_type":"Bearer","expires_in":3600}`

	tests := []struct {
		name          string
		pkce          bool
		secret        string
		authParams    map[string]string
		callback      url.Values
		openErr       error
		tokenStatus   int
		wantTokenReqs int // Including the retry of [oauth2.AuthStyleAutoDetect] after a failure.
		wantAuth      string
		wantCallback  int // The status of the callback response, which the browser displays to the user.
		wantHeader    string
		wantErr       bool
	}{
		{
			name:          "pkce",
			pkce:          true,
			callback:      url.Values{"code": {"c0de"}},
			tokenStatus:   http.StatusOK,
			wantTokenReqs: 1,
			wantAuth:      "Basic aWQ6", // "id:" (no client secret).
			wantCallback:  http.StatusOK,
			wantHeader:    "Bearer t0k3n",
		},
		{
			name:          "client_secret_with_auth_params",
			secret:        "secret",
			authParams:    map[string]string{"access_type": "offline"},
			callback:      url.Values{"code": {"c0de"}},
			tokenStatus:   http.StatusOK,
			wantTokenReqs: 1,
			wantAuth:      "Basic aWQ6c2VjcmV0", // "id:secret".
			wantCallback:  http.StatusOK,
			wantHeader:    "Bearer t0k3n",
		},
		{
			name:          "browser_error_does_not_abort",
			pkce:          true,
			callback:      url.Values{"code": {"c0de"}},
			openErr:       errors.New("no browser"),
			tokenStatus:   http.StatusOK,
			wantTokenReqs: 1,
			wantAuth:      "Basic aWQ6",
			wantCallback:  http.StatusOK,
			wantHeader:    "Bearer t0k3n",
		},
		{
			name:         "access_denied",
			pkce:         true,
			callback:     url.Values{"error": {"access_denied"}, "error_description": {"The user denied access."}},
			wantCallback: http.StatusBadRequest,
			wantErr:      true,
		},
		{
			name:          "exchange_rejected",
			pkce:          true,
			callback:      url.Values{"code": {"c0de"}},
			tokenStatus:   http.StatusBadRequest,
			wantTokenReqs: 2,
			wantAuth:      "Basic aWQ6",
			wantCallback:  http.StatusBadGateway,
			wantErr:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The token URL is never contacted: only the flow's client can reach the fake endpoint.
			endpoint := &fakeTokenEndpoint{status: tt.tokenStatus, body: `{"error":"invalid_grant"}`}
			if tt.tokenStatus == http.StatusOK {
				endpoint.body = okBody
			}

			addr := freeLoopbackAddr(t)
			callbackURL := "http://" + addr + "/callback"
			cfg := map[string]any{
				"type":                   "oauth",
				"oauth_client_id":        "id",
				"oauth_pkce":             tt.pkce,
				"oauth_scopes":           "read write",
				"oauth_auth_url":         testAuthURL, // Never contacted: the fake user agent plays its role.
				"oauth_callback_url":     callbackURL,
				"oauth_callback_address": addr,
				"oauth_token_url":        testTokenURL,
			}
			if tt.secret != "" {
				cfg["oauth_client_secret"] = tt.secret
			}
			if tt.authParams != nil {
				params := make(map[string]any, len(tt.authParams))
				for k, v := range tt.authParams {
					params[k] = v
				}
				cfg["oauth_auth_params"] = params
			}
			c, err := ParseConfig(cfg, &url.URL{Scheme: "https", Host: "example.com"}, tt.name)
			if err != nil {
				t.Fatalf("ParseConfig() error = %v", err)
			}

			authReq := make(chan url.Values, 1)
			callbackResp := make(chan callbackResponse, 1)
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: endpoint})
			ctx = browser.WithOpener(ctx, fakeUserAgent(t, tt.callback, tt.openErr, authReq, callbackResp))
			if err := c.DoInitialOAuthFlow(ctx); (err != nil) != tt.wantErr {
				t.Fatalf("Config.DoInitialOAuthFlow() error = %v, wantErr %v", err, tt.wantErr)
			}

			// What the user sees in the browser.
			select {
			case got := <-callbackResp:
				switch {
				case got.err != nil:
					t.Errorf("OAuth callback response error = %v, want a complete response", got.err)
				case got.status != tt.wantCallback:
					t.Errorf("OAuth callback response status = %d, want %d", got.status, tt.wantCallback)
				case got.body == "":
					t.Error("OAuth callback response body is empty, want a message for the user")
				}
			case <-time.After(RequestTimeout):
				t.Fatal("OAuth callback response never arrived")
			}

			// The authorization request, as received by the provider.
			var q url.Values
			select {
			case q = <-authReq:
			default:
				t.Fatal("Config.DoInitialOAuthFlow() didn't open the authorization URL")
			}
			challenge := q.Get("code_challenge")
			want := url.Values{
				"client_id":     {"id"},
				"redirect_uri":  {callbackURL},
				"response_type": {"code"},
				"scope":         {"read write"},
				"state":         {q.Get("state")},
			}
			for k, v := range tt.authParams {
				want.Set(k, v)
			}
			if tt.pkce {
				want.Set("code_challenge", challenge)
				want.Set("code_challenge_method", "S256")
			}
			if q.Get("state") == "" || (tt.pkce && challenge == "") {
				t.Errorf("authorization request has an empty state or PKCE challenge: %q", q.Encode())
			}
			if q.Encode() != want.Encode() {
				t.Errorf("authorization request = %q, want %q", q.Encode(), want.Encode())
			}

			// Sensitive parsed configuration details are cleared after the flow, regardless of its result.
			if c.oauthConfig != nil || c.oauthAuthParams != nil {
				t.Errorf("Config.DoInitialOAuthFlow() didn't clear parsed config details: %+v", c)
			}

			// The token must be reused, instead of requesting a new one for each header. After
			// a failed flow, there must be no token source that would keep requesting tokens.
			for range 2 {
				h, err := c.SetHeader(t.Context(), nil, tt.name)
				if err != nil {
					t.Fatalf("Config.SetHeader() error = %v", err)
				}
				if got := h.Get("Authorization"); got != tt.wantHeader {
					t.Errorf("Config.SetHeader() Authorization = %q, want %q", got, tt.wantHeader)
				}
			}

			// The token exchange requests, as received by the provider.
			tokenForms, tokenAuths := endpoint.requests()
			if len(tokenForms) != tt.wantTokenReqs {
				t.Fatalf("token endpoint got %d requests, want %d", len(tokenForms), tt.wantTokenReqs)
			}
			if tt.wantTokenReqs == 0 {
				return
			}
			form := tokenForms[0]
			if got := form.Get("grant_type"); got != "authorization_code" {
				t.Errorf("token request grant_type = %q, want %q", got, "authorization_code")
			}
			if got := form.Get("code"); got != "c0de" {
				t.Errorf("token request code = %q, want %q", got, "c0de")
			}
			if got := form.Get("redirect_uri"); got != callbackURL {
				t.Errorf("token request redirect_uri = %q, want %q", got, callbackURL)
			}
			verifier := form.Get("code_verifier")
			if tt.pkce && oauth2.S256ChallengeFromVerifier(verifier) != challenge {
				t.Errorf("token request code_verifier %q doesn't match the PKCE challenge %q", verifier, challenge)
			}
			if !tt.pkce && verifier != "" {
				t.Errorf("token request code_verifier = %q, want none without PKCE", verifier)
			}
			if tokenAuths[0] != tt.wantAuth {
				t.Errorf("token request Authorization = %q, want %q", tokenAuths[0], tt.wantAuth)
			}
		})
	}
}

// The wait is tested separately from the webhook, because [synctest] doesn't advance its
// fake clock while a goroutine is blocked on network I/O, such as a listening server.
func TestOAuthWebhookWait(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		result      *bool         // Nil means the callback never arrives.
		claimDelay  time.Duration // Before the callback's handler claims the flow.
		resultDelay time.Duration // Before the callback's result arrives (after the claim).
		wantErr     bool
		wantElapsed time.Duration
	}{
		{
			name:        "success_just_before_timeout",
			result:      new(true),
			claimDelay:  CallbackTimeout - time.Second,
			wantElapsed: CallbackTimeout - time.Second,
		},
		{
			name:        "failure",
			result:      new(false),
			claimDelay:  time.Second,
			wantErr:     true,
			wantElapsed: time.Second,
		},
		{
			name:        "timeout",
			wantErr:     true,
			wantElapsed: CallbackTimeout,
		},
		{
			// The flow must not return while the handler still uses the [Config].
			name:        "claimed_just_before_timeout_and_completed_after_it",
			result:      new(true),
			claimDelay:  CallbackTimeout - time.Second,
			resultDelay: RequestTimeout,
			wantElapsed: CallbackTimeout - time.Second + RequestTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				ow := (&Config{}).newOAuthWebhook(t.Context(), testCallbackAddr)
				if tt.result != nil {
					go func() {
						time.Sleep(tt.claimDelay)
						if !ow.tryClaim() {
							t.Error("oauthWebhook.tryClaim() = false for the first callback, want true")
							return
						}
						time.Sleep(tt.resultDelay)
						ow.result <- *tt.result
					}()
				}

				start := time.Now()
				if err := ow.wait(); (err != nil) != tt.wantErr {
					t.Errorf("oauthWebhook.wait() error = %v, wantErr %v", err, tt.wantErr)
				}
				if elapsed := time.Since(start); elapsed != tt.wantElapsed {
					t.Errorf("oauthWebhook.wait() returned after %v, want %v", elapsed, tt.wantElapsed)
				}
				if ow.tryClaim() {
					t.Error("oauthWebhook.tryClaim() = true after the flow ended, want late callbacks to be rejected")
				}
			})
		})
	}
}

// An unavailable callback address must fail the flow immediately, without opening the browser.
func TestConfigDoInitialOAuthFlowAuthorizationCodeAddressInUse(t *testing.T) {
	t.Parallel()
	sandbox.RequireLoopback(t)

	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenConfig.Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()

	c, err := ParseConfig(map[string]any{
		"type":                   "oauth",
		"oauth_client_id":        "id",
		"oauth_pkce":             true,
		"oauth_auth_url":         testAuthURL,
		"oauth_callback_url":     "http://" + addr + "/callback",
		"oauth_callback_address": addr,
		"oauth_token_url":        testTokenURL,
	}, &url.URL{Scheme: "https", Host: "example.com"}, t.Name())
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	ctx := browser.WithOpener(t.Context(), func(context.Context, string) error {
		t.Error("Config.DoInitialOAuthFlow() opened the browser, want an immediate error")
		return nil
	})
	start := time.Now()
	if err := c.DoInitialOAuthFlow(ctx); err == nil {
		t.Fatal("Config.DoInitialOAuthFlow() error = nil, want an error")
	}
	if elapsed := time.Since(start); elapsed >= CallbackTimeout {
		t.Errorf("Config.DoInitialOAuthFlow() failed after %v, want an immediate error", elapsed)
	}
	if h, err := c.SetHeader(t.Context(), nil, t.Name()); err != nil || h.Get("Authorization") != "" {
		t.Errorf("Config.SetHeader() = %v, %v, want no Authorization header after a failed flow", h, err)
	}
}

// Concurrent flows (e.g., of collectors) must not fail when their callback webhooks share the same address.
func TestConfigDoInitialOAuthFlowAuthorizationCodeConcurrent(t *testing.T) {
	t.Parallel()
	sandbox.RequireLoopback(t)

	addr := freeLoopbackAddr(t)
	newConfig := func(name string) *Config {
		c, err := ParseConfig(map[string]any{
			"type":                   "oauth",
			"oauth_client_id":        "id",
			"oauth_pkce":             true,
			"oauth_auth_url":         testAuthURL,
			"oauth_callback_url":     fmt.Sprintf("http://%s/callback", addr),
			"oauth_callback_address": addr,
			"oauth_token_url":        testTokenURL,
		}, &url.URL{Scheme: "https", Host: "example.com"}, name)
		if err != nil {
			t.Fatalf("ParseConfig() error = %v", err)
		}
		return c
	}
	first, second := newConfig("first"), newConfig("second")

	endpoint := &fakeTokenEndpoint{status: http.StatusOK, body: `{"access_token":"t0k3n","token_type":"Bearer"}`}
	authReq := make(chan url.Values, 2)
	callbackResp := make(chan callbackResponse, 2)
	userAgent := fakeUserAgent(t, url.Values{"code": {"c0de"}}, nil, authReq, callbackResp)

	// The first flow starts the second one while its own webhook is listening, and delays its own callback a bit,
	// so without serialization the second flow would try to listen on the same address before the first one ends.
	secondErr := make(chan error, 1)
	var started atomic.Bool
	opener := func(ctx context.Context, rawURL string) error {
		if started.CompareAndSwap(false, true) {
			go func() { secondErr <- second.DoInitialOAuthFlow(ctx) }()
			time.Sleep(100 * time.Millisecond)
		}
		return userAgent(ctx, rawURL)
	}

	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: endpoint})
	ctx = browser.WithOpener(ctx, opener)
	if err := first.DoInitialOAuthFlow(ctx); err != nil {
		t.Fatalf("first Config.DoInitialOAuthFlow() error = %v", err)
	}
	select {
	case err := <-secondErr:
		if err != nil {
			t.Fatalf("second Config.DoInitialOAuthFlow() error = %v", err)
		}
	case <-time.After(RequestTimeout):
		t.Fatal("second Config.DoInitialOAuthFlow() never returned")
	}

	for range 2 {
		if got := <-callbackResp; got.err != nil || got.status != http.StatusOK {
			t.Errorf("OAuth callback response = %d, %v, want %d", got.status, got.err, http.StatusOK)
		}
	}
	for _, c := range []*Config{first, second} {
		if h, err := c.SetHeader(t.Context(), nil, t.Name()); err != nil || h.Get("Authorization") != "Bearer t0k3n" {
			t.Errorf("Config.SetHeader() = %v, %v, want the token from the flow", h, err)
		}
	}
}

// A connection that's still active when the webhook shuts down (e.g., a stuck browser request)
// must be closed forcefully after [ShutdownTimeout], instead of blocking the flow indefinitely.
func TestOAuthWebhookShutdownForcesClose(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		ow := (&Config{}).newOAuthWebhook(t.Context(), testCallbackAddr)
		release := make(chan struct{})
		ow.Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release })

		ln := &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
		go func() { _ = ow.Serve(ln) }()
		client, server := net.Pipe()
		ln.conns <- server
		go func() { _, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n") }()
		synctest.Wait() // The handler is now blocked, so the connection is active.

		start := time.Now()
		ow.shutdown(t.Context())
		if elapsed := time.Since(start); elapsed != ShutdownTimeout {
			t.Errorf("oauthWebhook.shutdown() returned after %v, want %v", elapsed, ShutdownTimeout)
		}
		// A graceful shutdown alone would leave the connection open, so this read would block forever.
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Error("active connection is still open after oauthWebhook.shutdown(), want it closed")
		}
		close(release)
	})
}

// pipeListener is a [net.Listener] that accepts in-memory connections from [net.Pipe], which
// (unlike network connections) block durably, so servers that use it can run in [synctest] bubbles.
type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return pipeAddr{}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }
