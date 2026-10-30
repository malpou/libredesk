package main

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MetsaApp/platform-kit/edgeauth"
	"github.com/MetsaApp/platform-kit/edgeauth/edgeauthtest"
	activitylog "github.com/abhinavxd/libredesk/internal/activity_log"
	amodels "github.com/abhinavxd/libredesk/internal/auth/models"
	"github.com/abhinavxd/libredesk/internal/testutil"
	"github.com/abhinavxd/libredesk/internal/user"
	"github.com/jmoiron/sqlx"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
	"github.com/zerodha/logf"
)

const guardTestHost = "support.example.test"

type guardFixture struct {
	app    *App
	db     *sqlx.DB
	issuer *edgeauthtest.Issuer
}

func newGuardFixture(t *testing.T) *guardFixture {
	t.Helper()
	db := testutil.NewDB(t, "cmd_guard_identity")
	lo := logf.New(logf.Opts{Level: logf.FatalLevel})
	lang := testutil.NewI18n(t)
	users, err := user.New(lang, user.Opts{DB: db, Lo: &lo})
	if err != nil {
		t.Fatal(err)
	}
	activity, err := activitylog.New(activitylog.Opts{DB: db, Lo: &lo, I18n: lang})
	if err != nil {
		t.Fatal(err)
	}
	issuer := edgeauthtest.NewIssuer(t)
	v, err := edgeauth.New(issuer.Config(guardTestHost))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{lo: &lo, i18n: lang, user: users, activityLog: activity, guard: newGuardIdentity(v)}
	return &guardFixture{app: app, db: db, issuer: issuer}
}

func (f *guardFixture) agent(t *testing.T, email string, enabled bool) int {
	t.Helper()
	var id int
	if err := f.db.Get(&id, `INSERT INTO users (type, email, first_name, last_name, enabled)
		VALUES ('agent', $1, 'Agent', 'Smith', $2) RETURNING id`, email, enabled); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *guardFixture) loginCount(t *testing.T, userID int) int {
	t.Helper()
	var n int
	if err := f.db.Get(&n, `SELECT count(*) FROM activity_logs WHERE actor_id = $1 AND activity_type = 'agent_login'`, userID); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *guardFixture) token(email, sid string, roles ...string) string {
	return f.issuer.Mint(edgeauth.Identity{
		Subject: "sub-" + email, Email: email, EmailVerified: true, Roles: roles,
		SessionID: sid, AuthTime: time.Now(),
	}, guardTestHost)
}

// request builds a request on the guard host with the identity header (when token is set).
func (f *guardFixture) request(method, uri, token string) (*fastglue.Request, *fasthttp.RequestCtx) {
	var req fasthttp.Request
	req.Header.SetMethod(method)
	req.SetRequestURI(uri)
	req.Header.SetHost(guardTestHost)
	if token != "" {
		req.Header.Set(edgeauth.Header, token)
	}
	ctx := &fasthttp.RequestCtx{}
	ctx.Init(&req, &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1234}, nil)
	return &fastglue.Request{RequestCtx: ctx, Context: f.app}, ctx
}

// served is a handler that records the user the middleware put in the context.
func served(got *amodels.User) fastglue.FastRequestHandler {
	return func(r *fastglue.Request) error {
		*got, _ = r.RequestCtx.UserValue("user").(amodels.User)
		r.RequestCtx.SetStatusCode(http.StatusOK)
		return nil
	}
}

func TestGuardIdentity(t *testing.T) {
	f := newGuardFixture(t)
	known := f.agent(t, "agent@example.test", true)
	disabled := f.agent(t, "disabled@example.test", false)

	t.Run("a known agent is signed in, matched by email case-insensitively", func(t *testing.T) {
		var got amodels.User
		r, ctx := f.request(http.MethodGet, "/api/v1/agents/me", f.token("Agent@Example.test", "sid-1", "agent"))
		if err := auth(served(&got))(r); err != nil {
			t.Fatal(err)
		}
		if ctx.Response.StatusCode() != http.StatusOK || got.ID != known {
			t.Fatalf("status %d, user %d; want 200, %d", ctx.Response.StatusCode(), got.ID, known)
		}
		if m := ctx.UserValue("auth_method"); m != authMethodGuard {
			t.Errorf("auth_method = %v, want %s", m, authMethodGuard)
		}
		if c := ctx.Response.Header.PeekCookie("libredesk_session"); c != nil {
			t.Errorf("a Libredesk session cookie was set: %s", c)
		}
	})

	t.Run("a login is recorded once per guard session", func(t *testing.T) {
		before := f.loginCount(t, known)
		for range 3 {
			var got amodels.User
			r, _ := f.request(http.MethodGet, "/api/v1/agents/me", f.token("agent@example.test", "sid-2", "admin"))
			if err := auth(served(&got))(r); err != nil {
				t.Fatal(err)
			}
		}
		if n := f.loginCount(t, known) - before; n != 1 {
			t.Errorf("%d logins recorded for one guard session, want 1", n)
		}
	})

	t.Run("CSRF is still checked on writes", func(t *testing.T) {
		var got amodels.User
		r, ctx := f.request(http.MethodPost, "/api/v1/conversations", f.token("agent@example.test", "sid-1", "agent"))
		if err := auth(served(&got))(r); err != nil {
			t.Fatal(err)
		}
		if ctx.Response.StatusCode() != http.StatusForbidden || got.ID != 0 {
			t.Errorf("status %d, user %d; want 403 and no user", ctx.Response.StatusCode(), got.ID)
		}

		r, ctx = f.request(http.MethodPost, "/api/v1/conversations", f.token("agent@example.test", "sid-1", "agent"))
		ctx.Request.Header.SetCookie("csrf_token", "t")
		ctx.Request.Header.Set("X-CSRFTOKEN", "t")
		if err := auth(served(&got))(r); err != nil {
			t.Fatal(err)
		}
		if ctx.Response.StatusCode() != http.StatusOK || got.ID != known {
			t.Errorf("with CSRF: status %d, user %d; want 200, %d", ctx.Response.StatusCode(), got.ID, known)
		}
	})

	refused := []struct {
		name, token, loginCode string
		status                 int
	}{
		{"an unknown email gets no account", f.token("stranger@example.test", "sid-3", "agent"), oidcErrNoAccount, http.StatusForbidden},
		{"an identity without an email gets no account", f.token("", "sid-3", "agent"), oidcErrNoAccount, http.StatusForbidden},
		{"a disabled agent is refused", f.token("disabled@example.test", "sid-4", "agent"), oidcErrAccountDisabled, http.StatusForbidden},
		{"an identity without a libredesk role is refused", f.token("agent@example.test", "sid-5", "member"), oidcErrAccessDenied, http.StatusForbidden},
		{"an invalid token is 401", "not-a-jwt", "", http.StatusUnauthorized},
		{"a token for another host is 401", f.issuer.Mint(edgeauth.Identity{Subject: "s", Email: "agent@example.test", Roles: []string{"agent"}}, "other.example.test"), "", http.StatusUnauthorized},
		{"a token from another issuer's key is 401", edgeauthtest.NewIssuer(t).Mint(edgeauth.Identity{Subject: "s", Email: "agent@example.test", Roles: []string{"agent"}}, guardTestHost), "", http.StatusUnauthorized},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			var got amodels.User
			r, ctx := f.request(http.MethodGet, "/api/v1/agents/me", tc.token)
			if err := auth(served(&got))(r); err != nil {
				t.Fatal(err)
			}
			if ctx.Response.StatusCode() != tc.status || got.ID != 0 {
				t.Errorf("API: status %d, user %d; want %d and no user", ctx.Response.StatusCode(), got.ID, tc.status)
			}

			// The agent UI's pages: to the login page with its error, or the status.
			r, ctx = f.request(http.MethodGet, "/inboxes/assigned", tc.token)
			if err := authPage(served(&got))(r); err != nil {
				t.Fatal(err)
			}
			if tc.loginCode == "" {
				if ctx.Response.StatusCode() != tc.status {
					t.Errorf("page: status %d, want %d", ctx.Response.StatusCode(), tc.status)
				}
				return
			}
			loc := string(ctx.Response.Header.Peek("Location"))
			if ctx.Response.StatusCode() != http.StatusFound || !strings.Contains(loc, "error="+tc.loginCode) {
				t.Errorf("page: status %d to %q, want 302 to the login page with error=%s", ctx.Response.StatusCode(), loc, tc.loginCode)
			}

			// The login page shows that error instead of redirecting to itself.
			r, ctx = f.request(http.MethodGet, "/?error="+tc.loginCode, tc.token)
			var servedPage bool
			if err := notAuthPage(func(*fastglue.Request) error { servedPage = true; return nil })(r); err != nil {
				t.Fatal(err)
			}
			if !servedPage {
				t.Errorf("login page with error: not served (status %d)", ctx.Response.StatusCode())
			}
		})
	}
	if n := f.loginCount(t, disabled); n != 0 {
		t.Errorf("%d logins recorded for the disabled agent", n)
	}

	t.Run("the login page sends a signed-in agent to the inbox", func(t *testing.T) {
		r, ctx := f.request(http.MethodGet, "/", f.token("agent@example.test", "sid-1", "agent"))
		if err := notAuthPage(served(new(amodels.User)))(r); err != nil {
			t.Fatal(err)
		}
		if loc := string(ctx.Response.Header.Peek("Location")); ctx.Response.StatusCode() != http.StatusFound || !strings.HasSuffix(loc, "/inboxes/assigned") {
			t.Errorf("status %d to %q, want 302 to /inboxes/assigned", ctx.Response.StatusCode(), loc)
		}
	})

	t.Run("an API key still authenticates, ahead of any identity", func(t *testing.T) {
		bridge := f.agent(t, "bridge@example.test", true)
		key, secret, err := f.app.user.GenerateAPIKey(bridge)
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range []string{"", "not-a-jwt", f.token("agent@example.test", "sid-1", "agent")} {
			var got amodels.User
			r, ctx := f.request(http.MethodPost, "/api/v1/conversations", token)
			ctx.Request.Header.Set("Authorization", "token "+key+":"+secret)
			if err := auth(served(&got))(r); err != nil {
				t.Fatal(err)
			}
			if ctx.Response.StatusCode() != http.StatusOK || got.ID != bridge {
				t.Errorf("identity %q: status %d, user %d; want 200, %d", token, ctx.Response.StatusCode(), got.ID, bridge)
			}
			if m := ctx.UserValue("auth_method"); m != authMethodAPIKey {
				t.Errorf("auth_method = %v, want %s", m, authMethodAPIKey)
			}
		}
	})
}

// A token that cannot be checked because guard's keys are unreachable is 503, not a sign-in.
func TestGuardIdentityKeysUnavailable(t *testing.T) {
	f := newGuardFixture(t)
	f.agent(t, "agent@example.test", true)
	v, err := edgeauth.New(edgeauth.Config{JWKSURL: "http://127.0.0.1:1/jwks.json", Audiences: []string{guardTestHost}})
	if err != nil {
		t.Fatal(err)
	}
	f.app.guard = newGuardIdentity(v)

	var got amodels.User
	r, ctx := f.request(http.MethodGet, "/api/v1/agents/me", f.token("agent@example.test", "sid-1", "agent"))
	if err := auth(served(&got))(r); err != nil {
		t.Fatal(err)
	}
	if ctx.Response.StatusCode() != http.StatusServiceUnavailable || got.ID != 0 {
		t.Errorf("status %d, user %d; want 503 and no user", ctx.Response.StatusCode(), got.ID)
	}
}

func TestSeenSessions(t *testing.T) {
	s := seenSessions{m: map[string]time.Time{}}
	now := time.Now()
	if !s.first("a", now) || s.first("a", now.Add(time.Hour)) {
		t.Fatal("a session must count once")
	}
	if !s.first("a", now.Add(guardSeenTTL)) {
		t.Error("a session seen longer ago than the TTL counts again")
	}
	for i := range guardSeenMax + 1 {
		s.first(strconv.Itoa(i), now)
	}
	if len(s.m) > guardSeenMax {
		t.Errorf("%d entries kept, want at most %d", len(s.m), guardSeenMax)
	}
}
