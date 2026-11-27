package http

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"needful-t.ee/versipellis/internal/sandbox"
)

func TestReceiverListenTCPError(t *testing.T) {
	t.Parallel()

	r := &Receiver{}
	r.tcp = r.newTCPServer(http.DefaultServeMux)
	r.tcp.Addr = ":invalid"

	if ln, ok := r.listenTCP(t.Context()); ok {
		t.Errorf("Receiver.listenTCP() ok = true, want false")
		t.Cleanup(func() { _ = ln.Close() })
	}
}

func TestReceiverListenUDPError(t *testing.T) {
	t.Parallel()

	r := &Receiver{}
	r.udp = r.newUDPServer(http.DefaultServeMux)
	r.udp.Addr = ":invalid"

	if conn, ok := r.listenUDP(t.Context()); ok {
		t.Errorf("Receiver.listenUDP() ok = true, want false")
		t.Cleanup(func() { _ = conn.Close() })
	}
}

func TestReceiverServeTCPError(t *testing.T) {
	t.Parallel()
	sandbox.RequireLoopback(t)

	r := &Receiver{}
	r.tcp = r.newTCPServer(http.DefaultServeMux)
	r.tls = &tls.Config{MinVersion: 1} //gosec:disable G402 // Intentional unit test to cause an error.

	ln, ok := r.listenTCP(t.Context())
	if !ok {
		t.Fatalf("Receiver.listenTCP() ok = false, want true")
	}
	t.Cleanup(func() { _ = ln.Close() })

	if r.serveTCP(r.tcp, ln) {
		t.Errorf("Receiver.serveTCP() ok = true, want false")
	}
}

func TestReceiverServeUDPError(t *testing.T) {
	t.Parallel()
	sandbox.RequireLoopback(t)

	r := &Receiver{}
	r.udp = r.newUDPServer(http.DefaultServeMux)
	r.tls = &tls.Config{MinVersion: 1} //gosec:disable G402 // Intentional unit test to cause an error.

	conn, ok := r.listenUDP(t.Context())
	if !ok {
		t.Fatalf("Receiver.listenUDP() ok = false, want true")
	}
	t.Cleanup(func() { _ = conn.Close() })

	if r.serveUDP(r.udp, conn) {
		t.Errorf("Receiver.serveUDP() ok = true, want false")
	}
}

// The server's write deadline starts when the request arrives, so it must outlast the receiver's timeout, otherwise
// the response that [http.TimeoutHandler] writes when the timeout ends can never reach the client (it gets a
// connection error instead of a 503), and neither can late responses. A disabled timeout (0) must stay disabled.
func TestReceiverTCPServerTimeouts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		timeout    time.Duration
		hold       time.Duration // How long the handler takes, as long as it's allowed to.
		wantStatus int
		wantTime   time.Duration // Fake time until the client receives the response.
	}{
		{
			name:       "handler_exceeding_timeout",
			timeout:    2 * time.Second,
			hold:       time.Hour,
			wantStatus: http.StatusServiceUnavailable,
			wantTime:   2 * time.Second,
		},
		{
			name:       "handler_within_timeout",
			timeout:    2 * time.Second,
			hold:       time.Second,
			wantStatus: http.StatusAccepted,
			wantTime:   time.Second,
		},
		{
			name:       "no_timeout",
			timeout:    0,
			hold:       time.Hour,
			wantStatus: http.StatusAccepted,
			wantTime:   time.Hour,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				const dispatchDelay = time.Millisecond
				r := &Receiver{timeout: tt.timeout, maxHeaderSize: defaultMaxHeaderSize}
				release := make(chan struct{})
				defer close(release)
				var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					select {
					case <-time.After(tt.hold):
						w.WriteHeader(http.StatusAccepted)
					case <-release:
					}
				})
				if r.timeout > 0 { // The same as in [Receiver.Start].
					handler = http.TimeoutHandler(handler, r.timeout, "")
				}
				// In reality, handlers always start a bit after the server finished reading the request (when its write
				// deadline starts). The fake clock doesn't advance on its own, so without this the two would tie.
				next := handler
				handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					time.Sleep(dispatchDelay)
					next.ServeHTTP(w, req)
				})

				srv := r.newTCPServer(handler)
				ln := &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
				go func() { _ = srv.Serve(ln) }()
				defer srv.Close()

				client, server := net.Pipe()
				defer client.Close()
				ln.conns <- server
				start := time.Now()
				go func() { _, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n") }()

				resp, err := http.ReadResponse(bufio.NewReader(client), nil)
				if err != nil {
					t.Fatalf("client didn't receive a response: %v", err)
				}
				defer resp.Body.Close()
				if resp.StatusCode != tt.wantStatus {
					t.Errorf("response status = %d, want %d", resp.StatusCode, tt.wantStatus)
				}
				if elapsed := time.Since(start); elapsed != tt.wantTime+dispatchDelay {
					t.Errorf("client received the response after %v, want %v", elapsed, tt.wantTime+dispatchDelay)
				}
			})
		})
	}
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
