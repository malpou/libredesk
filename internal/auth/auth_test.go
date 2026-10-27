package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	amodels "github.com/abhinavxd/libredesk/internal/auth/models"
	"github.com/abhinavxd/libredesk/internal/kvstore"
	"github.com/abhinavxd/libredesk/internal/kvstore/kvtest"
	"github.com/abhinavxd/libredesk/internal/testutil"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
	"github.com/zerodha/logf"
	"github.com/zerodha/simplesessions/v3"
	"golang.org/x/oauth2"
)

type testOIDCKeys struct {
	payload []byte
}

func (k testOIDCKeys) VerifySignature(context.Context, string) ([]byte, error) {
	return k.payload, nil
}

func TestOIDCRejectsBlankEmail(t *testing.T) {
	for _, tt := range []struct {
		name     string
		email    string
		verified any
		want     bool
	}{
		{"verified", "agent@example.com", true, true},
		{"unverified", "agent@example.com", false, true},
		{"missing verification", "agent@example.com", nil, true},
		{"empty email", "", true, false},
		{"blank email", " \t", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			claims := map[string]any{"iss": "https://id.example.com", "aud": "desk", "sub": "test-user", "exp": time.Now().Add(time.Hour).Unix(), "email": tt.email}
			if tt.verified != nil {
				claims["email_verified"] = tt.verified
			}
			payload, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "token_type": "Bearer", "id_token": token})
			}))
			defer server.Close()
			lo := logf.New(logf.Opts{})
			a := &Auth{
				logger:       &lo,
				oidcClient:   server.Client(),
				oauthCfgs:    map[int]oauth2.Config{1: {ClientID: "desk", Endpoint: oauth2.Endpoint{TokenURL: server.URL}}},
				verifiers:    map[int]*oidc.IDTokenVerifier{1: oidc.NewVerifier("https://id.example.com", testOIDCKeys{payload}, &oidc.Config{ClientID: "desk"})},
				redirectURLs: map[int]func() (string, error){1: func() (string, error) { return "https://app.example.com/finish", nil }},
			}
			_, _, err = a.ExchangeOIDCToken(t.Context(), 1, "test-code")
			if (err == nil) != tt.want {
				t.Fatalf("exchange err = %v, want success %v", err, tt.want)
			}
		})
	}
}

func TestRemovedProviderStaysDisabledWhenReloadFails(t *testing.T) {
	lo := logf.New(logf.Opts{})
	a := &Auth{
		logger:       &lo,
		i18n:         testutil.NewI18n(t),
		oidcClient:   http.DefaultClient,
		oauthCfgs:    map[int]oauth2.Config{1: {ClientID: "desk", Endpoint: oauth2.Endpoint{AuthURL: "https://id.example.com/auth"}}},
		verifiers:    map[int]*oidc.IDTokenVerifier{1: nil},
		redirectURLs: map[int]func() (string, error){1: func() (string, error) { return "https://app.example.com/finish", nil }},
	}
	if _, err := a.LoginURL(1, "state"); err != nil {
		t.Fatal(err)
	}
	a.RemoveProvider(1)
	if err := a.Reload(Config{Providers: []Provider{{ID: 2, ProviderURL: ":invalid"}}}); err == nil {
		t.Fatal("expected failed discovery")
	}
	if _, err := a.LoginURL(1, "state"); err == nil {
		t.Fatal("removed provider still accepts logins")
	}
	if _, _, err := a.ExchangeOIDCToken(t.Context(), 1, "code"); err == nil {
		t.Fatal("removed provider still accepts callbacks")
	}
}

func TestSessionsRejectRevokedAndLegacyCookies(t *testing.T) {
	a, st, _ := sessionAuthForTest(t, time.Hour)
	first := saveTestSession(t, a, 1)
	second := saveTestSession(t, a, 1)
	other := saveTestSession(t, a, 2)
	requireSession(t, a, first, 1)
	requireSession(t, a, second, 1)
	if err := a.DestroyUserSessions(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	requireSession(t, a, first, 0 /** wantID **/)
	requireSession(t, a, second, 0 /** wantID **/)
	requireSession(t, a, other, 2)
	for _, key := range []string{userIndexKey(1), first, second} {
		if _, err := st.store.Get(t.Context(), key); !errors.Is(err, kvstore.ErrNotFound) {
			t.Fatalf("revoked key %q remains: err=%v", key, err)
		}
	}
	if err := a.DestroyUserSessions(t.Context(), 1); err != nil {
		t.Fatalf("repeated revocation: %v", err)
	}
	requireSession(t, a, saveTestSession(t, a, 1), 1)

	r := sessionRequest("" /** cookie **/)
	sess, err := a.sess.NewSession(r, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.SetMulti(map[string]any{"id": 1}); err != nil {
		t.Fatal(err)
	}
	requireSession(t, a, sess.ID(), 0 /** wantID **/)
}

func TestSessionLogoutPreservesOtherLogins(t *testing.T) {
	a, st, _ := sessionAuthForTest(t, time.Hour)
	first := saveTestSession(t, a, 1)
	second := saveTestSession(t, a, 1)
	if err := a.DestroySession(sessionRequest(first)); err != nil {
		t.Fatal(err)
	}
	requireSession(t, a, first, 0 /** wantID **/)
	requireSession(t, a, second, 1)
	if ids := indexedSessions(t, st, 1); len(ids) != 1 || ids[0] != second {
		t.Fatalf("remaining sessions = %v", ids)
	}
	if err := a.DestroySession(sessionRequest(first)); err != nil {
		t.Fatalf("repeated logout: %v", err)
	}
}

func TestSessionIndexExpiresAfterLastLogin(t *testing.T) {
	a, st, clock := sessionAuthForTest(t, time.Hour)
	first := saveTestSession(t, a, 1)
	clock.Advance(30 * time.Minute)
	second := saveTestSession(t, a, 1)
	if ttl := indexTTL(t, st, clock, 1); ttl != time.Hour {
		t.Fatalf("index TTL = %v, want %v", ttl, time.Hour)
	}
	clock.Advance(31 * time.Minute)
	requireSession(t, a, first, 0 /** wantID **/)
	requireSession(t, a, second, 1)
	if err := a.DestroyUserSessions(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	requireSession(t, a, second, 0 /** wantID **/)

	last := saveTestSession(t, a, 1)
	clock.Advance(time.Hour)
	requireSession(t, a, last, 0 /** wantID **/)
	if _, err := st.store.Get(t.Context(), userIndexKey(1)); !errors.Is(err, kvstore.ErrNotFound) {
		t.Fatalf("expired index remains: err=%v", err)
	}
}

func TestSessionIndexPreservesLongerSessionLifetime(t *testing.T) {
	a, st, clock := sessionAuthForTest(t, time.Hour)
	first := saveTestSession(t, a, 1)
	clock.Advance(10 * time.Minute)
	shorter, err := New(Config{SessionLifetime: time.Minute}, a.i18n, st.store, a.logger, nil /** dialControl **/)
	if err != nil {
		t.Fatal(err)
	}
	second := saveTestSession(t, shorter, 1)
	if ttl := indexTTL(t, st, clock, 1); ttl != 50*time.Minute {
		t.Fatalf("index expired before older sessions: TTL=%v", ttl)
	}
	if err := shorter.DestroyUserSessions(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	requireSession(t, shorter, first, 0 /** wantID **/)
	requireSession(t, shorter, second, 0 /** wantID **/)
}

func TestSessionIndexFailureDoesNotAuthenticate(t *testing.T) {
	a, st, _ := sessionAuthForTest(t, time.Hour)
	if err := st.store.Put(t.Context(), userIndexKey(1), []byte("wrong type"), 0 /** ttl **/); err != nil {
		t.Fatal(err)
	}
	r := sessionRequest("" /** cookie **/)
	if err := a.SaveSession(amodels.User{ID: 1}, r); err == nil {
		t.Fatal("login succeeded without indexing the session")
	}
	var cookie fasthttp.Cookie
	cookie.SetKey("libredesk_session")
	if !r.RequestCtx.Response.Header.Cookie(&cookie) {
		t.Fatal("missing session cookie")
	}
	user, err := a.ValidateSession(sessionRequest(string(cookie.Value())))
	if err != nil || user.ID != 0 {
		t.Fatalf("failed login acquired a user: id=%d err=%v", user.ID, err)
	}
}

func TestSessionRevocationFailurePreservesIndex(t *testing.T) {
	a, st, _ := sessionAuthForTest(t, time.Hour)
	cookie := saveTestSession(t, a, 1)
	st.kv.setDelete(func(string) error { return errors.New("kv unavailable") })
	if err := a.DestroyUserSessions(t.Context(), 1); err == nil {
		t.Fatal("revocation failure reported success")
	}
	st.kv.setDelete(nil)
	requireSession(t, a, cookie, 1)
	if ids := indexedSessions(t, st, 1); len(ids) != 1 {
		t.Fatalf("failed revocation lost its index: %v", ids)
	}
}

func TestSessionRevocationWaitsForRegistration(t *testing.T) {
	a, st, _ := sessionAuthForTest(t, time.Hour)
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	var once sync.Once
	// SetMulti writes the session fields with an Update of the session key; hold it there.
	st.kv.setUpdate(func(key string) error {
		if key != userIndexKey(1) {
			once.Do(func() {
				close(entered)
				<-release
			})
		}
		return nil
	})
	r := sessionRequest("" /** cookie **/)
	loginDone := make(chan error, 1)
	go func() { loginDone <- a.SaveSession(amodels.User{ID: 1}, r) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("login did not reach session registration")
	}
	revokeDone := make(chan error, 1)
	go func() { revokeDone <- a.DestroyUserSessions(t.Context(), 1) }()
	release <- struct{}{}
	if err := <-loginDone; err != nil {
		t.Fatal(err)
	}
	if err := <-revokeDone; err != nil {
		t.Fatal(err)
	}
	var cookie fasthttp.Cookie
	cookie.SetKey("libredesk_session")
	if !r.RequestCtx.Response.Header.Cookie(&cookie) {
		t.Fatal("missing session cookie")
	}
	requireSession(t, a, string(cookie.Value()), 0 /** wantID **/)
}

func TestSessionValidationUsesOneKVRead(t *testing.T) {
	a, st, clock := sessionAuthForTest(t, 0 /** lifetime **/)
	cookie := saveTestSession(t, a, 1)
	before := st.kv.ops.Load()
	requireSession(t, a, cookie, 1)
	if count := st.kv.ops.Load() - before; count != 1 {
		t.Fatalf("validation used %d KV operations, want 1", count)
	}
	if ttl := indexTTL(t, st, clock, 1); ttl != defaultSessionLifetime {
		t.Fatalf("default index TTL = %v", ttl)
	}
}

func TestSessionValuesPreserveLoginAndReplaceInvalidCookies(t *testing.T) {
	for _, cookieType := range []string{"missing", "unknown", "expired", "authenticated"} {
		t.Run(cookieType, func(t *testing.T) {
			a, _, clock := sessionAuthForTest(t, time.Hour)
			cookie := ""
			switch cookieType {
			case "unknown":
				cookie = "unknown-session"
			case "expired", "authenticated":
				cookie = saveTestSession(t, a, 1)
				if cookieType == "expired" {
					clock.Advance(2 * time.Hour)
				}
			}
			r := sessionRequest(cookie)
			if err := a.SetSessionValues(r, map[string]any{"oidc_state": "state"}); err != nil {
				t.Fatal(err)
			}
			var responseCookie fasthttp.Cookie
			responseCookie.SetKey("libredesk_session")
			hasCookie := r.RequestCtx.Response.Header.Cookie(&responseCookie)
			if cookieType == "authenticated" {
				if hasCookie {
					t.Fatal("SSO replaced the authenticated session cookie")
				}
				requireSession(t, a, cookie, 1)
			} else {
				if !hasCookie || len(responseCookie.Value()) != 64 || string(responseCookie.Value()) == cookie {
					t.Fatal("SSO did not issue a new random session cookie")
				}
				cookie = string(responseCookie.Value())
			}
			state, err := a.GetSessionValue(sessionRequest(cookie), "oidc_state")
			if err != nil || state != "state" {
				t.Fatalf("SSO state = %v, error = %v", state, err)
			}
		})
	}
}

func TestSessionValidationDoesNotCreateAnonymousSessions(t *testing.T) {
	a, st, _ := sessionAuthForTest(t, time.Hour)
	for _, cookie := range []string{"", "unknown-session"} {
		r := sessionRequest(cookie)
		if _, err := a.ValidateSession(r); !errors.Is(err, simplesessions.ErrInvalidSession) {
			t.Fatalf("invalid session accepted: %v", err)
		}
		if st.kv.writes.Load() != 0 || len(r.RequestCtx.Response.Header.Peek("Set-Cookie")) != 0 {
			t.Fatal("invalid session validation created an anonymous session")
		}
	}
}

// hookKV counts operations on a bucket and lets a test fail or hold them.
type hookKV struct {
	jetstream.KeyValue
	ops, writes atomic.Int64
	mu          sync.Mutex
	update, del func(key string) error
}

func (h *hookKV) setUpdate(fn func(string) error) { h.mu.Lock(); h.update = fn; h.mu.Unlock() }
func (h *hookKV) setDelete(fn func(string) error) { h.mu.Lock(); h.del = fn; h.mu.Unlock() }

func (h *hookKV) hook(fn *func(string) error, key string) error {
	h.mu.Lock()
	f := *fn
	h.mu.Unlock()
	if f != nil {
		return f(key)
	}
	return nil
}

func (h *hookKV) Get(ctx context.Context, key string) (jetstream.KeyValueEntry, error) {
	h.ops.Add(1)
	return h.KeyValue.Get(ctx, key)
}

func (h *hookKV) Put(ctx context.Context, key string, value []byte) (uint64, error) {
	h.ops.Add(1)
	h.writes.Add(1)
	return h.KeyValue.Put(ctx, key, value)
}

func (h *hookKV) Create(ctx context.Context, key string, value []byte, opts ...jetstream.KVCreateOpt) (uint64, error) {
	h.ops.Add(1)
	h.writes.Add(1)
	return h.KeyValue.Create(ctx, key, value, opts...)
}

func (h *hookKV) Update(ctx context.Context, key string, value []byte, revision uint64) (uint64, error) {
	h.ops.Add(1)
	h.writes.Add(1)
	if err := h.hook(&h.update, key); err != nil {
		return 0, err
	}
	return h.KeyValue.Update(ctx, key, value, revision)
}

func (h *hookKV) Delete(ctx context.Context, key string, opts ...jetstream.KVDeleteOpt) error {
	h.ops.Add(1)
	h.writes.Add(1)
	if err := h.hook(&h.del, key); err != nil {
		return err
	}
	return h.KeyValue.Delete(ctx, key, opts...)
}

type sessionTestStore struct {
	kv    *hookKV
	store *kvstore.Store
}

func userIndexKey(userID int) string { return kvstore.Key("user_sessions", strconv.Itoa(userID)) }

func indexedSessions(t *testing.T, st sessionTestStore, userID int) []string {
	t.Helper()
	e, err := st.store.Get(t.Context(), userIndexKey(userID))
	if err != nil {
		t.Fatalf("reading session index: %v", err)
	}
	var ids []string
	if err := json.Unmarshal(e.Value, &ids); err != nil {
		t.Fatal(err)
	}
	return ids
}

func indexTTL(t *testing.T, st sessionTestStore, clock *kvtest.Clock, userID int) time.Duration {
	t.Helper()
	e, err := st.store.Get(t.Context(), userIndexKey(userID))
	if err != nil {
		t.Fatalf("reading session index: %v", err)
	}
	return e.Expires.Sub(clock.Now())
}

func sessionAuthForTest(t *testing.T, lifetime time.Duration) (*Auth, sessionTestStore, *kvtest.Clock) {
	t.Helper()
	srv := kvtest.Start(t)
	raw, err := srv.JS.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "sessions"})
	if err != nil {
		t.Fatal(err)
	}
	kv := &hookKV{KeyValue: raw}
	st := kvstore.New(kv)
	clock := kvtest.NewClock()
	st.SetClock(clock.Now)
	lo := logf.New(logf.Opts{})
	a, err := New(Config{SessionLifetime: lifetime}, testutil.NewI18n(t), st, &lo, nil /** dialControl **/)
	if err != nil {
		t.Fatal(err)
	}
	return a, sessionTestStore{kv: kv, store: st}, clock
}

func sessionRequest(cookie string) *fastglue.Request {
	r := &fastglue.Request{RequestCtx: &fasthttp.RequestCtx{}}
	var req fasthttp.Request
	r.RequestCtx.Init(&req, nil /** remoteAddr **/, nil /** logger **/)
	r.RequestCtx.Request.SetRequestURI("https://app.example.com/")
	if cookie != "" {
		r.RequestCtx.Request.Header.SetCookie("libredesk_session", cookie)
	}
	return r
}

func saveTestSession(t *testing.T, a *Auth, id int) string {
	t.Helper()
	r := sessionRequest("" /** cookie **/)
	if err := a.SaveSession(amodels.User{ID: id}, r); err != nil {
		t.Fatal(err)
	}
	var cookie fasthttp.Cookie
	cookie.SetKey("libredesk_session")
	if !r.RequestCtx.Response.Header.Cookie(&cookie) {
		t.Fatal("missing session cookie")
	}
	return string(cookie.Value())
}

func requireSession(t *testing.T, a *Auth, cookie string, wantID int) {
	t.Helper()
	user, err := a.ValidateSession(sessionRequest(cookie))
	if wantID > 0 {
		if err != nil || user.ID != wantID {
			t.Fatalf("session user=%d err=%v, want user=%d", user.ID, err, wantID)
		}
	} else if !errors.Is(err, simplesessions.ErrInvalidSession) {
		t.Fatalf("revoked session accepted: user=%d err=%v", user.ID, err)
	}
}
