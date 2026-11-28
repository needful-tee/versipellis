package http

import (
	"context"
	"crypto/tls"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"needful-t.ee/versipellis/internal/sandbox"
	"needful-t.ee/versipellis/pkg/codec"
	"needful-t.ee/versipellis/pkg/config"
	"needful-t.ee/versipellis/pkg/dest"
)

func TestNewCollector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		base    *config.BaseCollector
		cfg     map[string]any
		wantErr bool

		wantURL     string
		wantMethod  string
		wantHeaders http.Header
		wantBody    string
		wantTimeout time.Duration
	}{
		{
			name:    "invalid_form_type",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "method": "POST", "form": "a=1"},
			wantErr: true,
		},
		{
			name:    "form_with_get_method",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "form": map[string]any{"a": "1"}},
			wantErr: true,
		},
		{
			name: "form_with_body",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg: map[string]any{
				"url": "https://example.com", "method": "POST", "body": "a=1", "form": map[string]any{"a": "1"},
			},
			wantErr: true,
		},
		{
			name: "form_with_default_content_type",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg: map[string]any{
				"url": "https://example.com", "method": "PUT", "form": map[string]any{"a": "1"},
			},
			wantURL:     "https://example.com",
			wantMethod:  http.MethodPut,
			wantHeaders: http.Header{contentTypeHeader: {formContentType}},
			wantBody:    "a=1",
			wantTimeout: defaultRequestTimeout,
		},
		{
			name: "form_with_explicit_content_type",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg: map[string]any{
				"url": "https://example.com", "method": "POST", "form": map[string]any{"a": "1"},
				"headers": map[string]any{"content-type": "text/plain"},
			},
			wantURL:     "https://example.com",
			wantMethod:  http.MethodPost,
			wantHeaders: http.Header{contentTypeHeader: {"text/plain"}},
			wantBody:    "a=1",
			wantTimeout: defaultRequestTimeout,
		},
		{
			name: "form_with_explicit_empty_content_type",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg: map[string]any{
				"url": "https://example.com", "method": "POST", "form": map[string]any{"a": "1"},
				"headers": map[string]any{"content-type": ""},
			},
			wantURL:     "https://example.com",
			wantMethod:  http.MethodPost,
			wantHeaders: http.Header{}, // Neither the default content type nor an empty one.
			wantBody:    "a=1",
			wantTimeout: defaultRequestTimeout,
		},
		{
			name: "body_with_explicit_empty_content_type",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg: map[string]any{
				"url": "https://example.com", "method": "POST", "body": "a=1",
				"headers": map[string]any{"content-type": "", "accept": "text/plain"},
			},
			wantURL:     "https://example.com",
			wantMethod:  http.MethodPost,
			wantHeaders: http.Header{"Accept": {"text/plain"}},
			wantBody:    "a=1",
			wantTimeout: defaultRequestTimeout,
		},
		{
			name: "form_with_query",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg: map[string]any{
				"url": "https://example.com?q1=1", "method": "POST",
				"query": map[string]any{"q2": "2"}, "form": map[string]any{"f1": "1", "f2": "2"},
			},
			wantURL:     "https://example.com?q1=1&q2=2",
			wantMethod:  http.MethodPost,
			wantHeaders: http.Header{contentTypeHeader: {formContentType}},
			wantBody:    "f1=1&f2=2",
			wantTimeout: defaultRequestTimeout,
		},
		{
			name: "json_body_with_default_content_type",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:  map[string]any{"url": "https://example.com", "method": "POST", "body": `{"a": 1}`},

			wantURL:     "https://example.com",
			wantMethod:  http.MethodPost,
			wantHeaders: http.Header{contentTypeHeader: {codec.JSON.ContentType()}},
			wantBody:    `{"a": 1}`,
			wantTimeout: defaultRequestTimeout,
		},
		{
			name: "json_body_with_explicit_content_type",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg: map[string]any{
				"url": "https://example.com", "method": "POST", "body": `{"a": 1}`,
				"headers": map[string]any{"content-type": "application/vnd.api+json"},
			},
			wantURL:     "https://example.com",
			wantMethod:  http.MethodPost,
			wantHeaders: http.Header{contentTypeHeader: {"application/vnd.api+json"}},
			wantBody:    `{"a": 1}`,
			wantTimeout: defaultRequestTimeout,
		},
		{
			name: "json_body_with_explicit_empty_content_type",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg: map[string]any{
				"url": "https://example.com", "method": "POST", "body": `{"a": 1}`,
				"headers": map[string]any{"content-type": ""},
			},
			wantURL:     "https://example.com",
			wantMethod:  http.MethodPost,
			wantHeaders: http.Header{}, // Neither the default content type nor an empty one.
			wantBody:    `{"a": 1}`,
			wantTimeout: defaultRequestTimeout,
		},
		{
			name: "body_without_default_content_type",
			base: &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:  map[string]any{"url": "https://example.com", "method": "POST", "body": "a=1"},

			wantURL:     "https://example.com",
			wantMethod:  http.MethodPost,
			wantHeaders: http.Header{},
			wantBody:    "a=1",
			wantTimeout: defaultRequestTimeout,
		},
		{
			name:    "invalid_url",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"http": map[string]any{"url": ""}},
			wantErr: true,
		},
		{
			name:    "invalid_method",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "method": "DELETE"},
			wantErr: true,
		},
		{
			name:    "invalid_query_type",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "query": 123},
			wantErr: true,
		},
		{
			name:    "invalid_format",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "format": "invalid"},
			wantErr: true,
		},
		{
			name:    "headers_not_a_table",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "headers": "Accept: application/json"},
			wantErr: true,
		},
		{
			name:    "body_file_not_found",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "body_file": "/nonexistent/file"},
			wantErr: true,
		},
		{
			name:    "invalid_retries",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "retries": "invalid"},
			wantErr: true,
		},
		{
			name:    "tls_not_a_table",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "tls": "invalid"},
			wantErr: true,
		},
		{
			name:        "http_url_with_tls_config",
			base:        &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:         map[string]any{"url": "http://example.com", "tls": map[string]any{"min_version": "1.3"}},
			wantErr:     false, // Logs a warning, does not abort.
			wantURL:     "http://example.com",
			wantMethod:  http.MethodGet,
			wantHeaders: http.Header{},
			wantTimeout: defaultRequestTimeout,
		},
		{
			name:    "invalid_timeout",
			base:    &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:     map[string]any{"url": "https://example.com", "timeout": "not-a-duration"},
			wantErr: true,
		},
		{
			name:        "minimal_valid_config",
			base:        &config.BaseCollector{Type: config.CollectorTypeHTTP},
			cfg:         map[string]any{"url": "https://example.com"},
			wantURL:     "https://example.com",
			wantMethod:  http.MethodGet,
			wantHeaders: http.Header{},
			wantTimeout: defaultRequestTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			coll, gotErr := NewCollector(tt.base, tt.cfg)
			if (gotErr != nil) != tt.wantErr {
				t.Fatalf("NewCollector() error = %v, wantErr %v", gotErr, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if b := coll.Base(); !reflect.DeepEqual(b, tt.base) {
				t.Errorf("Collector.Base() = %+v, want %+v", b, tt.base)
			}
			if got := coll.url.String(); got != tt.wantURL {
				t.Errorf("Collector.url = %q, want %q", got, tt.wantURL)
			}
			if coll.method != tt.wantMethod {
				t.Errorf("Collector.method = %q, want %q", coll.method, tt.wantMethod)
			}
			if !reflect.DeepEqual(coll.headers, tt.wantHeaders) {
				t.Errorf("Collector.headers = %+v, want %+v", coll.headers, tt.wantHeaders)
			}
			if got := string(coll.body); got != tt.wantBody {
				t.Errorf("Collector.body = %q, want %q", got, tt.wantBody)
			}
			if coll.timeout != tt.wantTimeout {
				t.Errorf("Collector.timeout = %v, want %v", coll.timeout, tt.wantTimeout)
			}
		})
	}
}

func TestLoadBody(t *testing.T) {
	t.Parallel()

	bodyWithSpaces := "\n text  \n\n"
	jsonObject := "\n { \"a\": 1, \"a\": [true, null] } \n"
	tempDir := t.TempDir()
	files := map[string]string{
		"empty.txt":      "",
		"body.txt":       bodyWithSpaces,
		"json.txt":       jsonObject,
		"invalid.json":   bodyWithSpaces,
		"line.ndjson":    jsonObject,
		"UPPER.NDJSON":   jsonObject,
		"json_no_ext":    jsonObject,
		"text_no_ext":    bodyWithSpaces,
		"json.unknown-x": jsonObject,
		"text.unknown-x": bodyWithSpaces,
	}
	for name, content := range files {
		//gosec:disable G304 // Unit test.
		if err := os.WriteFile(filepath.Join(tempDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The MIME types of JSON and NDJSON file extensions are fixed, but those of other extensions come from
	// Go's built-in table, which OS tables may override, so these tests don't assume their exact values.
	jsonType, ndjsonType := codec.JSON.ContentType(), codec.NDJSON.ContentType()
	textType := mime.TypeByExtension(".txt")
	if textType == "" || textType == jsonType {
		t.Fatalf("unusable MIME type for the .txt file extension: %q", textType)
	}

	tests := []struct {
		name     string
		body     string
		path     string
		form     any
		method   string
		want     string
		wantType string
		wantErr  bool
	}{
		{
			name:     "valid_form",
			form:     map[string]any{"b": "2", "a": "1"},
			method:   http.MethodPost,
			want:     "a=1&b=2",
			wantType: formContentType,
		},
		{
			name: "empty_form_is_no_body",
			form: map[string]any{},
		},
		{
			name:   "empty_form_with_get_method",
			form:   map[string]any{},
			method: http.MethodGet,
		},
		{
			name: "empty_form_with_inline_body",
			body: bodyWithSpaces,
			form: map[string]any{},
			want: bodyWithSpaces,
		},
		{
			name:    "valid_form_with_get_method",
			form:    map[string]any{"a": "1"},
			method:  http.MethodGet,
			wantErr: true,
		},
		{
			name:    "both_form_and_body",
			body:    bodyWithSpaces,
			form:    map[string]any{"a": "1"},
			wantErr: true,
		},
		{
			name:    "both_form_and_file",
			path:    filepath.Join(tempDir, "body.txt"),
			form:    map[string]any{"a": "1"},
			wantErr: true,
		},
		{
			name:    "form_and_body_and_file",
			body:    bodyWithSpaces,
			path:    filepath.Join(tempDir, "body.txt"),
			form:    map[string]any{"a": "1"},
			wantErr: true,
		},
		{
			name:    "form_not_a_table",
			form:    "a=1",
			wantErr: true,
		},
		{
			name:    "form_value_not_a_string",
			form:    map[string]any{"a": int64(1)},
			wantErr: true,
		},
		{
			name:    "no_body_or_file_or_form",
			wantErr: false,
		},
		{
			name:    "both_body_and_file",
			body:    bodyWithSpaces,
			path:    filepath.Join(tempDir, "body.txt"),
			wantErr: true,
		},
		{
			name:    "valid_inline_body_with_get_method",
			body:    bodyWithSpaces,
			method:  http.MethodGet,
			wantErr: true,
		},
		{
			name: "valid_inline_body",
			body: bodyWithSpaces,
			want: bodyWithSpaces,
		},
		{
			name:    "body_file_not_found",
			path:    filepath.Join(tempDir, "nonexistent"),
			wantErr: true,
		},
		{
			name:    "body_file_is_directory",
			path:    tempDir,
			wantErr: true,
		},
		{
			name:    "empty_body_file",
			path:    filepath.Join(tempDir, "empty.txt"),
			wantErr: true,
		},
		{
			name:    "valid_body_file_with_get_method",
			path:    filepath.Join(tempDir, "body.txt"),
			method:  http.MethodGet,
			wantErr: true,
		},
		{
			name:     "valid_body_file",
			path:     filepath.Join(tempDir, "body.txt"),
			want:     bodyWithSpaces,
			wantType: textType,
		},
		{
			name:     "inline_json_object",
			body:     jsonObject,
			want:     jsonObject,
			wantType: jsonType,
		},
		{
			name:     "inline_json_array",
			body:     "[]",
			want:     "[]",
			wantType: jsonType,
		},
		{
			name: "inline_json_string",
			body: `"{}"`,
			want: `"{}"`,
		},
		{
			name: "inline_json_number",
			body: "42",
			want: "42",
		},
		{
			name: "inline_truncated_json",
			body: `{"a": 1`,
			want: `{"a": 1`,
		},
		{
			name: "inline_json_with_trailing_data",
			body: "{} {}",
			want: "{} {}",
		},
		{
			name: "inline_json_with_byte_order_mark",
			body: "\ufeff{}",
			want: "\ufeff{}",
		},
		{
			name: "inline_whitespace_only",
			body: " \n",
			want: " \n",
		},
		{
			name:     "file_extension_overrides_json_content",
			path:     filepath.Join(tempDir, "json.txt"),
			want:     jsonObject,
			wantType: textType,
		},
		{
			name:     "file_extension_without_json_content",
			path:     filepath.Join(tempDir, "invalid.json"),
			want:     bodyWithSpaces,
			wantType: jsonType,
		},
		{
			name:     "ndjson_file_extension_overrides_json_content",
			path:     filepath.Join(tempDir, "line.ndjson"),
			want:     jsonObject,
			wantType: ndjsonType,
		},
		{
			name:     "uppercase_ndjson_file_extension",
			path:     filepath.Join(tempDir, "UPPER.NDJSON"),
			want:     jsonObject,
			wantType: ndjsonType,
		},
		{
			name:     "json_file_without_extension",
			path:     filepath.Join(tempDir, "json_no_ext"),
			want:     jsonObject,
			wantType: jsonType,
		},
		{
			name: "text_file_without_extension",
			path: filepath.Join(tempDir, "text_no_ext"),
			want: bodyWithSpaces,
		},
		{
			name:     "json_file_with_unrecognized_extension",
			path:     filepath.Join(tempDir, "json.unknown-x"),
			want:     jsonObject,
			wantType: jsonType,
		},
		{
			name: "text_file_with_unrecognized_extension",
			path: filepath.Join(tempDir, "text.unknown-x"),
			want: bodyWithSpaces,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := map[string]any{"body": tt.body, "body_file": tt.path, "form": tt.form}
			gotBytes, gotType, gotErr := loadBody(cfg, tt.method)
			if (gotErr != nil) != tt.wantErr {
				t.Fatalf("loadBody() error = %v, wantErr %v", gotErr, tt.wantErr)
			}
			if gotStr := string(gotBytes); gotStr != tt.want {
				t.Fatalf("loadBody() got = %q, want %q", gotStr, tt.want)
			}
			if gotType != tt.wantType {
				t.Fatalf("loadBody() content type = %q, want %q", gotType, tt.wantType)
			}
		})
	}
}

func TestCollectorStart(t *testing.T) {
	t.Parallel()
	sandbox.RequireLoopback(t)

	tests := []struct {
		name  string
		proto string
		tls   bool
	}{
		{
			name:  "http1_success",
			proto: config.CollectorTypeHTTP,
			tls:   false,
		},
		{
			name:  "sender_error",
			proto: config.CollectorTypeHTTP,
			tls:   false,
		},
		{
			name:  "http2_success",
			proto: config.CollectorTypeHTTP,
			tls:   true,
		},
		{
			name:  "http3_failed_retries",
			proto: config.CollectorTypeHTTP3,
			tls:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.tls && r.TLS == nil {
					t.Errorf("expected TLS connection, got nil")
				}
				w.WriteHeader(http.StatusOK)
			}))
			if tt.tls {
				server.EnableHTTP2 = true
				server.StartTLS()
			} else {
				server.Start()
			}
			t.Cleanup(server.Close)

			base, err := config.NewBaseCollector(
				map[string]any{"type": tt.proto, "schedule": "@once", "destination": "test"},
				tt.name, map[string]config.Sender{"": nil, "test": dest.Discard},
			)
			if err != nil {
				t.Fatalf("config.NewBaseCollector() error: %v", err)
			}

			coll, err := NewCollector(base, map[string]any{
				"method": http.MethodGet, "url": server.URL, "timeout": "100ms",
				"retries": map[string]any{"type": retryTypeStatic, "max_attempts": int64(2), "interval": "1ms"},
			})
			if err != nil {
				t.Fatalf("NewCollector() error: %v", err)
			}

			coll.transportID += tt.name
			fakeClient := server.Client()
			fakeTransport, _ := fakeClient.Transport.(*http.Transport)
			transportH2.Set(coll.transportID, fakeTransport)

			if !coll.Start(t.Context()) {
				t.Fatal("Collector.Start() = false, want true")
			}

			<-coll.Done() // Wait for the collector's goroutine to finish its work.
		})
	}
}

func TestCollectorStartWithFailedOAuthFlow(t *testing.T) {
	t.Parallel()
	sandbox.RequireLoopback(t)

	var tokenRequests, dataRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			dataRequests.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		tokenRequests.Add(1)
		w.Header().Set(contentTypeHeader, "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	t.Cleanup(server.Close)

	base, err := config.NewBaseCollector(
		map[string]any{"type": config.CollectorTypeHTTP, "schedule": "@once", "destination": "test"},
		t.Name(), map[string]config.Sender{"": nil, "test": dest.Discard},
	)
	if err != nil {
		t.Fatalf("config.NewBaseCollector() error: %v", err)
	}
	coll, err := NewCollector(base, map[string]any{
		"method": http.MethodGet, "url": server.URL + "/data", "timeout": "1s",
		"auth": map[string]any{
			"type":                "oauth",
			"oauth_client_id":     "id",
			"oauth_client_secret": "secret",
			"oauth_token_url":     server.URL + "/token", // Plain HTTP is allowed for loopback hosts.
		},
	})
	if err != nil {
		t.Fatalf("NewCollector() error: %v", err)
	}

	if coll.Start(t.Context()) {
		t.Fatal("Collector.Start() = true, want false")
	}

	// A failed start must still close the collector, so nothing waiting for it hangs.
	select {
	case <-coll.Done():
	case <-time.After(time.Second):
		t.Fatal("Collector.Done() isn't closed after a failed start")
	}
	coll.Close(t.Context()) // Must be a no-op after the collector already closed itself.

	// With the default [oauth2.AuthStyleAutoDetect], after the first failure, oauth2
	// tries again with the client credentials in the form, instead of the header.
	if got := tokenRequests.Load(); got != 2 {
		t.Errorf("token endpoint got %d requests, want 2", got)
	}
	if got := dataRequests.Load(); got != 0 {
		t.Errorf("data endpoint got %d requests, want 0", got)
	}
}

func TestScheduleNextRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		schedule string
		cancel   bool
		isAsync  bool
	}{
		{
			name:     "context_cancellation",
			schedule: "@daily",
			cancel:   true,
		},
		{
			name:     "behind_schedule_skip",
			schedule: "@every 1s",
			isAsync:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				base, err := config.NewBaseCollector(
					map[string]any{"type": config.CollectorTypeHTTP, "schedule": tt.schedule},
					tt.name, map[string]config.Sender{"": dest.Discard},
				)
				if err != nil {
					t.Fatalf("config.NewBaseCollector() error: %v", err)
				}

				coll, err := NewCollector(base, map[string]any{"method": http.MethodGet, "url": "https://example.com"})
				if err != nil {
					t.Fatalf("NewCollector() error: %v", err)
				}

				// A real client would send a real request, which would fail and leave a retry pending when the test ends.
				transport := &fakeBlockingTransport{started: make(chan struct{}, 10), unblock: make(chan struct{})}
				close(transport.unblock) // Respond immediately.
				coll.client = &http.Client{Transport: transport}

				ctx, cancel := context.WithCancel(t.Context())
				schedCtx, execCtx := coll.state.StartWith(ctx)
				if tt.cancel {
					cancel()
				} else {
					t.Cleanup(cancel)
				}

				if !tt.isAsync {
					coll.scheduleNext(schedCtx, execCtx, time.Now())
					return
				}

				go coll.scheduleNext(schedCtx, execCtx, time.Now().Add(-5*time.Second))
				synctest.Wait()
				cancel()
				<-coll.Done()
			})
		})
	}
}

func TestCollectorCloseTimeout(t *testing.T) {
	t.Parallel()

	testTimeout := CloseTimeout + AbortTimeout

	tests := []struct {
		name    string
		start   bool
		timeout time.Duration
		want    time.Duration
	}{
		{
			name:    "with_client",
			start:   true,
			timeout: testTimeout,
			want:    testTimeout,
		},
		{
			name:    "negative_timeout",
			start:   true,
			timeout: -1 * time.Second,
			want:    testTimeout,
		},
		{
			name:    "without_client",
			timeout: testTimeout,
			start:   false,
			want:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				base := &config.BaseCollector{Type: config.CollectorTypeHTTP}
				coll, err := NewCollector(base, map[string]any{
					"method":  http.MethodGet,
					"url":     "https://example.com",
					"timeout": tt.timeout.String(),
				})
				if err != nil {
					t.Fatalf("NewCollector() error: %v", err)
				}

				// Test case 1: Close() before Start() should return immediately and have no effect.
				start := time.Now()
				coll.Close(t.Context())
				if got := time.Since(start); got != 0 {
					t.Fatalf("Collector.Close(1) timeout behaved unexpectedly: got %v, want %v", got, 0)
				}

				// Test case 2: Close() after Start() should block until current request is done / the timeout expires.
				coll.state.StartWith(t.Context())
				if tt.start {
					coll.client = clientH2(&tls.Config{}, 0, coll.timeout, tt.name)
					coll.state.InProgress.Go(func() {
						synctest.Sleep(testTimeout * 2)
					})
				}

				start = time.Now()
				coll.Close(t.Context())
				if got := time.Since(start); got != tt.want {
					t.Errorf("Collector.Close(2) timeout behaved unexpectedly: got %v, want %v", got, tt.want)
				}

				synctest.Sleep(testTimeout * 3)
			})
		})
	}
}

type fakeBlockingTransport struct {
	started chan struct{}
	unblock chan struct{}
	count   atomic.Int32
}

func (f *fakeBlockingTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	f.count.Add(1)

	select {
	case f.started <- struct{}{}:
	default:
	}

	<-f.unblock

	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
}

func TestCollectorConcurrencyLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		limit     int64
		wantCount int32
	}{
		{
			name:      "0_no_concurrency",
			limit:     0,
			wantCount: 1,
		},
		{
			name:      "1_no_concurrency",
			limit:     1,
			wantCount: 1,
		},
		{
			name:      "2_bounded_concurrency",
			limit:     2,
			wantCount: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				base, err := config.NewBaseCollector(
					map[string]any{"type": config.CollectorTypeHTTP, "schedule": "@every 1s", "concurrency_limit": tt.limit},
					tt.name, map[string]config.Sender{"": dest.Discard},
				)
				if err != nil {
					t.Fatalf("config.NewBaseCollector() error: %v", err)
				}

				coll, err := NewCollector(base, map[string]any{"method": http.MethodGet, "url": "https://example.com"})
				if err != nil {
					t.Fatalf("NewCollector() error: %v", err)
				}

				transport := &fakeBlockingTransport{
					started: make(chan struct{}, 10),
					unblock: make(chan struct{}),
				}
				coll.client = &http.Client{Transport: transport}
				ctx, cancel := context.WithCancel(t.Context())
				t.Cleanup(cancel)
				schedCtx, execCtx := coll.state.StartWith(ctx)

				go coll.scheduleNext(schedCtx, execCtx, time.Now())

				// Advance to 1st tick.
				synctest.Sleep(time.Second)
				<-transport.started

				// Advance to 2nd tick.
				synctest.Sleep(time.Second)
				if tt.limit > 1 {
					<-transport.started
				}

				// Unblock ongoing requests and let them finish.
				close(transport.unblock)
				synctest.Sleep(10 * time.Millisecond)

				cancel()
				synctest.Wait()

				if got := transport.count.Load(); got != tt.wantCount {
					t.Errorf("executed requests = %d, want %d", got, tt.wantCount)
				}
			})
		})
	}
}

func TestCollectorRequestWithConcurrencyLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		canceled  bool // The scheduling context is canceled, i.e., the collector is shutting down.
		semFull   bool // The concurrency limit was already reached.
		wantCount int32
	}{
		{
			name:      "sends_request",
			wantCount: 1,
		},
		{
			name:    "skips_at_concurrency_limit",
			semFull: true,
		},
		{
			name:     "skips_when_canceled",
			canceled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			base, err := config.NewBaseCollector(
				map[string]any{"type": config.CollectorTypeHTTP, "schedule": "@once"},
				tt.name, map[string]config.Sender{"": dest.Discard},
			)
			if err != nil {
				t.Fatalf("config.NewBaseCollector() error: %v", err)
			}
			coll, err := NewCollector(base, map[string]any{"method": http.MethodGet, "url": "https://example.com"})
			if err != nil {
				t.Fatalf("NewCollector() error: %v", err)
			}

			transport := &fakeBlockingTransport{started: make(chan struct{}, 1), unblock: make(chan struct{})}
			close(transport.unblock) // Respond immediately.
			coll.client = &http.Client{Transport: transport}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			schedCtx, execCtx := coll.state.StartWith(ctx)
			if tt.canceled {
				cancel()
			}

			// The semaphore has a free slot unless the test case fills it, so skipping the request
			// in the "canceled" test case is only possible because of the cancellation check.
			sem := make(chan struct{}, 1)
			if tt.semFull {
				sem <- struct{}{}
			}

			coll.requestWithConcurrencyLimit(schedCtx, execCtx, sem, time.Now())
			coll.state.InProgress.Wait()

			if got := transport.count.Load(); got != tt.wantCount {
				t.Errorf("sent requests = %d, want %d", got, tt.wantCount)
			}
			wantLen := 0
			if tt.semFull {
				wantLen = 1
			}
			if got := len(sem); got != wantLen {
				t.Errorf("semaphore slots in use = %d, want %d", got, wantLen)
			}
		})
	}
}
