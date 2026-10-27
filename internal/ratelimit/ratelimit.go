package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/abhinavxd/libredesk/internal/kvstore"
	realip "github.com/ferluci/fast-realip"
	"github.com/valyala/fasthttp"
)

// window is the length of one rate limit window.
const window = time.Minute

// Rule defines a rate limiting rule for a named group of endpoints.
type Rule struct {
	Name              string
	Enabled           bool
	RequestsPerMinute int
}

// Limiter handles rate limiting with a fixed-window counter per rule and client IP.
type Limiter struct {
	store *kvstore.Store
	rules map[string]Rule
}

// New creates a new rate limiter.
func New(store *kvstore.Store) *Limiter {
	return &Limiter{
		store: store,
		rules: make(map[string]Rule),
	}
}

// AddRule registers a named rate limiting rule.
func (l *Limiter) AddRule(rule Rule) {
	l.rules[rule.Name] = rule
}

// Check checks if the request should be rate limited for the given rule.
func (l *Limiter) Check(ctx *fasthttp.RequestCtx, ruleName string) error {
	rule, ok := l.rules[ruleName]
	if !ok || !rule.Enabled {
		return nil
	}

	clientIP := realip.FromRequest(ctx)
	now := time.Now()
	nowUnix := now.Unix()
	windowStart := now.Truncate(window).Unix()
	key := kvstore.Key("rl", ruleName, clientIP, strconv.FormatInt(windowStart, 10))

	// Fail open: a store outage must not lock everyone out.
	sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	count, err := l.store.Incr(sctx, key, 2*window)
	if err != nil {
		return nil
	}

	limit := int64(rule.RequestsPerMinute)

	ctx.Response.Header.Set("X-RateLimit-Limit", strconv.Itoa(rule.RequestsPerMinute))
	ctx.Response.Header.Set("X-RateLimit-Reset", strconv.FormatInt(nowUnix+60, 10))

	if count > limit {
		ctx.Response.Header.Set("X-RateLimit-Remaining", "0")
		ctx.Response.Header.Set("Retry-After", "60")
		ctx.Response.Header.Set("Content-Type", "application/json")
		ctx.SetStatusCode(fasthttp.StatusTooManyRequests)
		ctx.SetBodyString(`{"status":"error","message":"Rate limit exceeded"}`)
		return fmt.Errorf("rate limit exceeded")
	}

	remaining := max(int(limit-count), 0)
	ctx.Response.Header.Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	return nil
}
