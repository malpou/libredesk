package kvstore_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abhinavxd/libredesk/internal/kvstore"
	"github.com/abhinavxd/libredesk/internal/kvstore/kvtest"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/zerodha/fastcache/v4"
)

var ctx = context.Background()

func TestKeyIsValidAndInjective(t *testing.T) {
	inputs := [][]string{
		{"session", "abcDEF123_-"},
		{"sends", "conv", "john+otp@example.com"},
		{"rl", "auth", "2001:db8::1", "1700000000"},
		{"page", "/hc/support/en/search?q=refund&x=1"},
		{"a.b"}, {"a", "b"},
		{""}, {"="},
	}
	srv := kvtest.Start(t)
	st := srv.Bucket("keys")
	seen := map[string]string{}
	for _, in := range inputs {
		k := kvstore.Key(in...)
		if prev, ok := seen[k]; ok {
			t.Errorf("Key(%q) collides with Key(%s)", in, prev)
		}
		seen[k] = fmt.Sprintf("%q", in)
		if err := st.Put(ctx, k, []byte("x"), 0); err != nil {
			t.Errorf("Key(%q) = %q is not a valid KV key: %v", in, k, err)
		}
	}
	if got := kvstore.Key("session", "abc"); got != "session.abc" {
		t.Errorf("plain parts must stay readable, got %q", got)
	}
}

func TestExpiryIsEnforcedOnRead(t *testing.T) {
	st := kvtest.Bucket(t, "expiry")
	clock := kvtest.NewClock()
	st.SetClock(clock.Now)

	if err := st.Put(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	e, err := st.Get(ctx, "k")
	if err != nil || string(e.Value) != "v" {
		t.Fatalf("Get = (%q, %v), want v", e.Value, err)
	}
	if got := e.Expires.Sub(clock.Now()); got != time.Minute {
		t.Errorf("expires in %s, want 1m", got)
	}
	clock.Advance(time.Minute)
	if _, err := st.Get(ctx, "k"); !errors.Is(err, kvstore.ErrNotFound) {
		t.Errorf("expired Get err = %v, want ErrNotFound", err)
	}

	if err := st.Put(ctx, "forever", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	clock.Advance(365 * 24 * time.Hour)
	if _, err := st.Get(ctx, "forever"); err != nil {
		t.Errorf("a zero TTL must never expire: %v", err)
	}
}

func TestCreateIsSetNX(t *testing.T) {
	st := kvtest.Bucket(t, "create")
	clock := kvtest.NewClock()
	st.SetClock(clock.Now)

	if _, err := st.Create(ctx, "k", []byte("1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(ctx, "k", []byte("2"), time.Minute); !errors.Is(err, kvstore.ErrExists) {
		t.Errorf("second Create err = %v, want ErrExists", err)
	}

	// An expired value the bucket has not reclaimed yet must not block a new Create.
	clock.Advance(time.Minute)
	if _, err := st.Create(ctx, "k", []byte("3"), time.Minute); err != nil {
		t.Errorf("Create over an expired value: %v", err)
	}

	// Nor must a deleted one.
	if err := st.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(ctx, "k", []byte("4"), time.Minute); err != nil {
		t.Errorf("Create over a deleted value: %v", err)
	}
}

func TestCASWrites(t *testing.T) {
	st := kvtest.Bucket(t, "cas")

	rev, err := st.Create(ctx, "k", []byte("a"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(ctx, "k", []byte("b"), time.Time{}, rev); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(ctx, "k", []byte("c"), time.Time{}, rev); !errors.Is(err, kvstore.ErrConflict) {
		t.Errorf("stale Update err = %v, want ErrConflict", err)
	}
	if err := st.DeleteRevision(ctx, "k", rev); !errors.Is(err, kvstore.ErrConflict) {
		t.Errorf("stale DeleteRevision err = %v, want ErrConflict", err)
	}
	e, _ := st.Get(ctx, "k")
	if err := st.DeleteRevision(ctx, "k", e.Revision); err != nil {
		t.Errorf("DeleteRevision with the latest revision: %v", err)
	}
	if _, err := st.Get(ctx, "k"); !errors.Is(err, kvstore.ErrNotFound) {
		t.Errorf("Get after delete err = %v, want ErrNotFound", err)
	}
}

func TestIncrIsAtomicAndKeepsFirstExpiry(t *testing.T) {
	st := kvtest.Bucket(t, "incr")
	clock := kvtest.NewClock()
	st.SetClock(clock.Now)

	const n = 50
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := st.Incr(ctx, "c", time.Minute); err != nil {
				t.Errorf("Incr: %v", err)
			}
		}()
	}
	wg.Wait()
	e, err := st.Get(ctx, "c")
	if err != nil || string(e.Value) != fmt.Sprint(n) {
		t.Fatalf("counter = (%q, %v), want %d", e.Value, err, n)
	}

	clock.Advance(30 * time.Second)
	if _, err := st.Incr(ctx, "c", time.Minute); err != nil {
		t.Fatal(err)
	}
	clock.Advance(30 * time.Second)
	if _, err := st.Get(ctx, "c"); !errors.Is(err, kvstore.ErrNotFound) {
		t.Error("later increments must not extend the window set by the first")
	}
	if n, _ := st.Incr(ctx, "c", time.Minute); n != 1 {
		t.Errorf("Incr after expiry = %d, want 1", n)
	}
}

func TestOpenRequiresProvisionedBucket(t *testing.T) {
	srv := kvtest.Start(t)

	_, err := kvstore.Open(ctx, srv.JS, "missing", 0)
	if err == nil || !strings.Contains(err.Error(), `"missing" does not exist`) {
		t.Errorf("Open on a missing bucket err = %v, want a does-not-exist error", err)
	}
	if _, err := srv.JS.KeyValue(ctx, "missing"); !errors.Is(err, jetstream.ErrBucketNotFound) {
		t.Error("Open must never create a bucket")
	}

	if _, err := srv.JS.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "short", TTL: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if _, err := kvstore.Open(ctx, srv.JS, "short", time.Hour); err == nil {
		t.Error("Open must reject a bucket whose max age is shorter than the TTLs written to it")
	}
	if _, err := kvstore.Open(ctx, srv.JS, "short", time.Minute); err != nil {
		t.Errorf("Open with a long enough max age: %v", err)
	}
}

func TestSessionStoreHardCutoff(t *testing.T) {
	st := kvtest.Bucket(t, "sessions")
	clock := kvtest.NewClock()
	st.SetClock(clock.Now)
	ss := kvstore.NewSessionStore(st, time.Hour)

	if err := ss.Create("sid"); err != nil {
		t.Fatal(err)
	}
	if err := ss.SetMulti("sid", map[string]interface{}{"id": 42, "email": "a@b.c", "admin": true}); err != nil {
		t.Fatal(err)
	}
	vals, err := ss.GetMulti("sid", "id", "email", "admin", "missing")
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := ss.Int(vals["id"], nil); id != 42 {
		t.Errorf("id = %v", vals["id"])
	}
	if email, _ := ss.String(vals["email"], nil); email != "a@b.c" {
		t.Errorf("email = %v", vals["email"])
	}
	if admin, _ := ss.Bool(vals["admin"], nil); !admin {
		t.Errorf("admin = %v", vals["admin"])
	}
	if _, err := ss.String(vals["missing"], nil); err != kvstore.ErrNil {
		t.Errorf("missing field err = %v, want ErrNil", err)
	}

	// Activity must not push the cutoff back.
	clock.Advance(50 * time.Minute)
	if err := ss.Set("sid", "seen", "1"); err != nil {
		t.Fatal(err)
	}
	clock.Advance(10 * time.Minute)
	if _, err := ss.GetMulti("sid", "id"); err != kvstore.ErrInvalidSession {
		t.Errorf("session past its lifetime err = %v, want ErrInvalidSession", err)
	}

	if err := ss.Create("sid2"); err != nil {
		t.Fatal(err)
	}
	if err := ss.Destroy("sid2"); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.Get("sid2", "id"); err != kvstore.ErrInvalidSession {
		t.Errorf("destroyed session err = %v, want ErrInvalidSession", err)
	}
}

func TestSessionStoreConcurrentWritesKeepEveryField(t *testing.T) {
	ss := kvstore.NewSessionStore(kvtest.Bucket(t, "sessions"), time.Hour)
	if err := ss.Create("sid"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ss.Set("sid", fmt.Sprint("f", i), "v"); err != nil {
				t.Errorf("Set: %v", err)
			}
		}()
	}
	wg.Wait()
	all, err := ss.GetAll("sid")
	if err != nil || len(all) != 20 {
		t.Errorf("GetAll = %d fields (%v), want 20", len(all), err)
	}
}

func TestPageCacheSkipsOversizedPages(t *testing.T) {
	pc := kvstore.NewPageCache(kvtest.Bucket(t, "pages"), 64*1024)

	small := fastcache.Item{ContentType: "text/html", ETag: "e1", Blob: []byte("<p>hi</p>")}
	if err := pc.Put("ns", "g", "/small", small, time.Minute); err != nil {
		t.Fatal(err)
	}
	got, err := pc.Get("ns", "g", "/small")
	if err != nil || string(got.Blob) != "<p>hi</p>" || got.ETag != "e1" || got.ContentType != "text/html" {
		t.Errorf("Get = (%+v, %v)", got, err)
	}

	big := fastcache.Item{Blob: make([]byte, 64*1024)}
	if err := pc.Put("ns", "g", "/big", big, time.Minute); err != nil {
		t.Errorf("an oversized page must be skipped, not fail: %v", err)
	}
	if got, err := pc.Get("ns", "g", "/big"); err != nil || len(got.Blob) != 0 {
		t.Errorf("oversized page Get = (%d bytes, %v), want a miss", len(got.Blob), err)
	}

	if err := pc.DelGroup("ns", "g"); err != nil {
		t.Fatal(err)
	}
	if got, _ := pc.Get("ns", "g", "/small"); len(got.Blob) != 0 {
		t.Error("DelGroup must invalidate every page in the group")
	}
}
