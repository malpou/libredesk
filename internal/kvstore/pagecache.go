package kvstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/zerodha/fastcache/v4"
)

// PageCache is a fastcache.Store keeping one KV value per cached URI.
//
// Each namespace/group has a generation key; cached URIs are keyed under the current
// generation, so DelGroup only has to replace the generation for every page in the group to
// become unreachable. The orphaned values are reclaimed by their TTL and the bucket's MaxAge.
type PageCache struct {
	st *Store
	// maxValue is the largest value written; bigger pages are served uncached.
	maxValue int
}

// NewPageCache returns a page cache over st. maxValue should be the server's max payload.
func NewPageCache(st *Store, maxValue int) *PageCache {
	return &PageCache{st: st, maxValue: maxValue}
}

// pageMeta is the JSON header stored in front of a cached blob.
type pageMeta struct {
	ContentType string `json:"ct"`
	ETag        string `json:"etag"`
	Compression string `json:"comp"`
}

// Get returns the cached page for uri. A miss returns an empty item and no error.
func (c *PageCache) Get(namespace, group, uri string) (fastcache.Item, error) {
	ctx := context.Background()
	gen, err := c.generation(ctx, namespace, group, false)
	if err != nil || gen == "" {
		return fastcache.Item{}, err
	}
	e, err := c.st.Get(ctx, pageKey(namespace, group, gen, uri))
	if errors.Is(err, ErrNotFound) {
		return fastcache.Item{}, nil
	}
	if err != nil {
		return fastcache.Item{}, err
	}

	i := bytes.IndexByte(e.Value, '\n')
	if i < 0 {
		return fastcache.Item{}, errors.New("kvstore: cached page has no header")
	}
	var m pageMeta
	if err := json.Unmarshal(e.Value[:i], &m); err != nil {
		return fastcache.Item{}, err
	}
	return fastcache.Item{ContentType: m.ContentType, ETag: m.ETag, Compression: m.Compression, Blob: e.Value[i+1:]}, nil
}

// Put caches a page for ttl.
func (c *PageCache) Put(namespace, group, uri string, b fastcache.Item, ttl time.Duration) error {
	meta, err := json.Marshal(pageMeta{ContentType: b.ContentType, ETag: b.ETag, Compression: b.Compression})
	if err != nil {
		return err
	}
	val := make([]byte, 0, len(meta)+1+len(b.Blob))
	val = append(append(append(val, meta...), '\n'), b.Blob...)
	// Leave headroom for the expiry header and the message envelope.
	if c.maxValue > 0 && len(val) > c.maxValue-1024 {
		return nil
	}

	ctx := context.Background()
	gen, err := c.generation(ctx, namespace, group, true)
	if err != nil {
		return err
	}
	return c.st.Put(ctx, pageKey(namespace, group, gen, uri), val, ttl)
}

// Del drops the cached page for uri.
func (c *PageCache) Del(namespace, group, uri string) error {
	ctx := context.Background()
	gen, err := c.generation(ctx, namespace, group, false)
	if err != nil || gen == "" {
		return err
	}
	return c.st.Delete(ctx, pageKey(namespace, group, gen, uri))
}

// DelGroup invalidates every cached page in the groups by starting a new generation.
func (c *PageCache) DelGroup(namespace string, groups ...string) error {
	ctx := context.Background()
	for _, g := range groups {
		if err := c.st.Put(ctx, genKey(namespace, g), []byte(newGeneration()), 0); err != nil {
			return err
		}
	}
	return nil
}

// generation returns the group's current generation, starting one if create is set.
func (c *PageCache) generation(ctx context.Context, namespace, group string, create bool) (string, error) {
	e, err := c.st.Get(ctx, genKey(namespace, group))
	switch {
	case err == nil:
		return string(e.Value), nil
	case !errors.Is(err, ErrNotFound):
		return "", err
	case !create:
		return "", nil
	}
	gen := newGeneration()
	if _, err := c.st.Create(ctx, genKey(namespace, group), []byte(gen), 0); errors.Is(err, ErrExists) {
		// Another writer started the generation first; use theirs.
		return c.generation(ctx, namespace, group, false)
	} else if err != nil {
		return "", err
	}
	return gen, nil
}

func genKey(namespace, group string) string { return Key("gen", namespace, group) }

func pageKey(namespace, group, gen, uri string) string {
	sum := sha256.Sum256([]byte(uri))
	return Key("page", namespace, group, gen, hex.EncodeToString(sum[:]))
}

func newGeneration() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
