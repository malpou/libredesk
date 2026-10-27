package ratelimit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/abhinavxd/libredesk/internal/kvstore/kvtest"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/logf"
)

func request() *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("X-Real-Ip", "2001:db8::1")
	return ctx
}

func testLogger(buf *bytes.Buffer) *logf.Logger {
	lo := logf.New(logf.Opts{Writer: buf})
	return &lo
}

func TestCheckLimitsPerWindow(t *testing.T) {
	var logs bytes.Buffer
	l := New(kvtest.Bucket(t, "ratelimit"), testLogger(&logs))
	l.AddRule(Rule{Name: "auth", Enabled: true, RequestsPerMinute: 3})

	for i := range 3 {
		ctx := request()
		if err := l.Check(ctx, "auth"); err != nil {
			t.Fatalf("request %d limited: %v", i, err)
		}
		if got := string(ctx.Response.Header.Peek("X-RateLimit-Limit")); got != "3" {
			t.Errorf("X-RateLimit-Limit = %q, want 3", got)
		}
	}
	if logs.Len() != 0 {
		t.Fatalf("allowed requests produced a log: %s", logs.String())
	}
	ctx := request()
	if err := l.Check(ctx, "auth"); err == nil {
		t.Fatal("fourth request in the window must be limited")
	}
	if ctx.Response.StatusCode() != fasthttp.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", ctx.Response.StatusCode())
	}
	if got := string(ctx.Response.Header.Peek("Retry-After")); got != "60" {
		t.Errorf("Retry-After = %q, want 60", got)
	}
}

func TestCheckFailsOpenWhenStoreIsDown(t *testing.T) {
	var logs bytes.Buffer
	srv := kvtest.Start(t)
	l := New(srv.Bucket("ratelimit"), testLogger(&logs))
	l.AddRule(Rule{Name: "auth", Enabled: true, RequestsPerMinute: 1})
	srv.Shutdown()

	for range 3 {
		if err := l.Check(request(), "auth"); err != nil {
			t.Fatalf("a store outage must not rate limit requests: %v", err)
		}
	}
	if !strings.Contains(logs.String(), "level=warn") || !strings.Contains(logs.String(), "rule=auth") {
		t.Fatalf("missing storage failure warning: %s", logs.String())
	}
}
