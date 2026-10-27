// Package kvtest runs an embedded JetStream server for tests of code built on kvstore.
package kvtest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/abhinavxd/libredesk/internal/kvstore"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Server is an embedded, in-process JetStream server.
type Server struct {
	t  *testing.T
	ns *server.Server
	nc *nats.Conn
	JS jetstream.JetStream
}

// Start runs a server that is shut down when the test ends.
func Start(t *testing.T) *Server {
	t.Helper()
	ns, err := server.NewServer(&server.Options{
		JetStream:  true,
		StoreDir:   t.TempDir(),
		DontListen: true,
		NoLog:      true,
		NoSigs:     true,
	})
	if err != nil {
		t.Fatalf("starting embedded nats server: %v", err)
	}
	ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		t.Fatal("embedded nats server did not become ready")
	}
	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		t.Fatalf("connecting to embedded nats server: %v", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream context: %v", err)
	}
	t.Cleanup(func() {
		nc.Close()
		ns.Shutdown()
		ns.WaitForShutdown()
	})
	return &Server{t: t, ns: ns, nc: nc, JS: js}
}

// Bucket creates a bucket and returns a store bound to it.
func (s *Server) Bucket(name string) *kvstore.Store {
	s.t.Helper()
	ctx := context.Background()
	if _, err := s.JS.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: name}); err != nil {
		s.t.Fatalf("creating bucket %q: %v", name, err)
	}
	st, err := kvstore.Open(ctx, s.JS, name, 0)
	if err != nil {
		s.t.Fatal(err)
	}
	return st
}

// Shutdown stops the server early, to test behaviour when the store is unreachable.
func (s *Server) Shutdown() {
	s.nc.Close()
	s.ns.Shutdown()
}

// Bucket is a shortcut that starts a server and creates one bucket on it.
func Bucket(t *testing.T, name string) *kvstore.Store {
	t.Helper()
	return Start(t).Bucket(name)
}

// Clock is a manually advanced clock for kvstore.Store.SetClock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock returns a clock starting at the current time, truncated to the millisecond
// precision expiries are stored with.
func NewClock() *Clock { return &Clock{t: time.Now().Truncate(time.Millisecond)} }

// Now returns the clock's time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}
