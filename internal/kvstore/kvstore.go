// Package kvstore is a small TTL-aware key/value layer over NATS JetStream KV buckets.
//
// Every value carries its own expiry, stamped in front of the payload, and reads treat an
// expired value as missing. Expiry therefore works on any bucket configuration; the bucket's
// MaxAge only reclaims storage and must be at least as long as the longest TTL written to it.
package kvstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

var (
	// ErrNotFound is returned when a key is missing, deleted or expired.
	ErrNotFound = errors.New("kvstore: key not found")
	// ErrExists is returned by Create when a live value is already stored.
	ErrExists = errors.New("kvstore: key exists")
	// ErrConflict is returned when the revision passed to a CAS write is no longer the latest.
	ErrConflict = errors.New("kvstore: revision conflict")
)

const (
	defaultTimeout = 5 * time.Second
	// maxCASBackoff caps the jittered wait between Mutate retries under contention.
	maxCASBackoff = 20 * time.Millisecond
)

// plainSegmentRe matches key segments that are stored as is; anything else is base64url-encoded.
var plainSegmentRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Entry is a live value read from the store.
type Entry struct {
	Value    []byte
	Revision uint64
	// Expires is when the value stops being readable. Zero means it never expires.
	Expires time.Time
}

// Store wraps one KV bucket.
type Store struct {
	kv  jetstream.KeyValue
	now func() time.Time
}

// Open binds to an existing bucket. It never creates one: buckets are provisioned with their
// replication and MaxAge by infrastructure, so a missing bucket is a deployment error.
// minAge is the longest TTL the caller writes; a bucket whose MaxAge would evict values
// before that is rejected too.
func Open(ctx context.Context, js jetstream.JetStream, bucket string, minAge time.Duration) (*Store, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	kv, err := js.KeyValue(ctx, bucket)
	if err != nil {
		if errors.Is(err, jetstream.ErrBucketNotFound) {
			return nil, fmt.Errorf("NATS KV bucket %q does not exist; it must be provisioned before libredesk starts", bucket)
		}
		return nil, fmt.Errorf("binding NATS KV bucket %q: %w", bucket, err)
	}
	st, err := kv.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading NATS KV bucket %q status: %w", bucket, err)
	}
	if age := st.TTL(); age > 0 && age < minAge {
		return nil, fmt.Errorf("NATS KV bucket %q has max age %s, shorter than the %s libredesk keeps values for", bucket, age, minAge)
	}
	return New(kv), nil
}

// New wraps an already bound bucket.
func New(kv jetstream.KeyValue) *Store {
	return &Store{kv: kv, now: time.Now}
}

// SetClock replaces the clock used for expiry; meant for tests.
func (s *Store) SetClock(now func() time.Time) {
	s.now = now
}

// Now returns the store's current time.
func (s *Store) Now() time.Time {
	return s.now()
}

// ExpiresIn returns the expiry for a value written now with the given TTL; ttl <= 0 never expires.
func (s *Store) ExpiresIn(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return s.now().Add(ttl)
}

// Get returns the live value for key, or ErrNotFound.
func (s *Store) Get(ctx context.Context, key string) (Entry, error) {
	e, live, err := s.get(ctx, key)
	if err != nil {
		return Entry{}, err
	}
	if !live {
		return Entry{}, ErrNotFound
	}
	return e, nil
}

// Put writes val unconditionally.
func (s *Store) Put(ctx context.Context, key string, val []byte, ttl time.Duration) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	_, err := s.kv.Put(ctx, key, encode(val, s.ExpiresIn(ttl)))
	return err
}

// Create writes val only if no live value exists for key (SETNX); it returns ErrExists otherwise.
func (s *Store) Create(ctx context.Context, key string, val []byte, ttl time.Duration) (uint64, error) {
	return s.create(ctx, key, val, s.ExpiresIn(ttl))
}

// Update writes val with the given expiry if rev is still the latest revision of key.
func (s *Store) Update(ctx context.Context, key string, val []byte, expires time.Time, rev uint64) (uint64, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	n, err := s.kv.Update(ctx, key, encode(val, expires), rev)
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) || errors.Is(err, jetstream.ErrKeyExists) {
		return 0, ErrConflict
	}
	return n, err
}

// Delete removes key. Deleting a missing key is not an error.
func (s *Store) Delete(ctx context.Context, keys ...string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	for _, k := range keys {
		if err := s.kv.Delete(ctx, k); err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
			return err
		}
	}
	return nil
}

// DeleteRevision removes key only if rev is still its latest revision, so exactly one of
// several concurrent readers of the same value can consume it.
func (s *Store) DeleteRevision(ctx context.Context, key string, rev uint64) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	err := s.kv.Delete(ctx, key, jetstream.LastRevision(rev))
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) || errors.Is(err, jetstream.ErrKeyExists) {
		return ErrConflict
	}
	return err
}

// Mutate runs a compare-and-swap loop on key. fn gets the live entry (found is false if there
// is none) and returns the new value and expiry; returning a nil value deletes the key.
// fn may run several times and must not have side effects. Conflicts are retried with
// jittered backoff until ctx (default 5s) runs out.
func (s *Store) Mutate(ctx context.Context, key string, fn func(cur Entry, found bool) ([]byte, time.Time, error)) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			backoff := min(time.Millisecond<<min(attempt, 5), maxCASBackoff)
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w: %w", ErrConflict, ctx.Err())
			case <-time.After(rand.N(backoff) + 1):
			}
		}

		cur, live, err := s.get(ctx, key)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		view := cur
		if !live {
			view = Entry{}
		}
		val, expires, err := fn(view, live)
		if err != nil {
			return err
		}

		switch {
		case val == nil && live:
			err = s.DeleteRevision(ctx, key, cur.Revision)
		case val == nil:
			return nil
		case cur.Revision == 0:
			_, err = s.create(ctx, key, val, expires)
		default:
			// Also overwrites an expired value, which still holds the latest revision.
			_, err = s.Update(ctx, key, val, expires, cur.Revision)
		}
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrExists) {
			continue
		}
		return err
	}
}

// Incr increments the integer stored at key and returns the new value. The expiry is set by
// the first increment and kept by later ones, like INCR followed by EXPIRE on a new key.
func (s *Store) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	var n int64
	err := s.Mutate(ctx, key, func(cur Entry, found bool) ([]byte, time.Time, error) {
		if !found {
			n = 1
			return []byte("1"), s.ExpiresIn(ttl), nil
		}
		v, err := strconv.ParseInt(string(cur.Value), 10, 64)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("kvstore: %q holds a non-integer value", key)
		}
		n = v + 1
		return []byte(strconv.FormatInt(n, 10)), cur.Expires, nil
	})
	return n, err
}

// Key joins parts into a valid KV key. Parts made of [a-zA-Z0-9_-] are kept as is so keys stay
// readable; any other part (emails, IPv6 addresses, URIs) is base64url-encoded behind a '='
// marker, which plain parts can never contain, so distinct inputs never collide.
func Key(parts ...string) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		if plainSegmentRe.MatchString(p) {
			out[i] = p
		} else {
			out[i] = "=" + base64.RawURLEncoding.EncodeToString([]byte(p))
		}
	}
	return strings.Join(out, ".")
}

// get returns the latest stored value for key and whether it is still live. An expired value
// is returned with its revision so CAS writes can replace it.
func (s *Store) get(ctx context.Context, key string) (Entry, bool, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	raw, err := s.kv.Get(ctx, key)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return Entry{}, false, ErrNotFound
		}
		return Entry{}, false, err
	}
	val, expires, err := decode(raw.Value())
	if err != nil {
		return Entry{}, false, fmt.Errorf("kvstore: %q: %w", key, err)
	}
	e := Entry{Value: val, Revision: raw.Revision(), Expires: expires}
	return e, expires.IsZero() || s.now().Before(expires), nil
}

func (s *Store) create(ctx context.Context, key string, val []byte, expires time.Time) (uint64, error) {
	cctx, cancel := withTimeout(ctx)
	rev, err := s.kv.Create(cctx, key, encode(val, expires))
	cancel()
	if err == nil {
		return rev, nil
	}
	if !errors.Is(err, jetstream.ErrKeyExists) {
		return 0, err
	}

	// A value is stored, but it may have expired without the bucket reclaiming it yet.
	cur, live, err := s.get(ctx, key)
	switch {
	case errors.Is(err, ErrNotFound):
		return 0, ErrExists
	case err != nil:
		return 0, err
	case live:
		return 0, ErrExists
	}
	rev, err = s.Update(ctx, key, val, expires, cur.Revision)
	if errors.Is(err, ErrConflict) {
		return 0, ErrExists
	}
	return rev, err
}

// encode prefixes val with its expiry in Unix milliseconds (0 = never) and a newline,
// which keeps values readable with `nats kv get`.
func encode(val []byte, expires time.Time) []byte {
	var ms int64
	if !expires.IsZero() {
		ms = expires.UnixMilli()
	}
	b := strconv.AppendInt(make([]byte, 0, len(val)+16), ms, 10)
	b = append(b, '\n')
	return append(b, val...)
}

func decode(b []byte) ([]byte, time.Time, error) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return nil, time.Time{}, errors.New("value has no expiry header")
	}
	ms, err := strconv.ParseInt(string(b[:i]), 10, 64)
	if err != nil {
		return nil, time.Time{}, errors.New("value has a malformed expiry header")
	}
	var expires time.Time
	if ms > 0 {
		expires = time.UnixMilli(ms)
	}
	return b[i+1:], expires, nil
}

func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultTimeout)
}
