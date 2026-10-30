package main

// Sign agents in from guard's identity (metsa fork, COR-1084).
//
// With auth.guard_identity on, the edge proxy in front of Libredesk (guard)
// owns the browser login and hands every signed-in request upstream as a
// short-lived signed JWT in the x-bastion-identity header. Libredesk verifies
// it with platform-kit's edgeauth and maps it to the agent account with the
// same email, exactly as the OIDC callback does: no auto-provisioning, a
// disabled account is refused, and the agent's own Libredesk roles stay the
// permissions. No Libredesk session is minted for such a request. API keys
// still win over everything, and without the header the session path works
// as upstream's.

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MetsaApp/platform-kit/edgeauth"
	"github.com/abhinavxd/libredesk/internal/envelope"
	"github.com/abhinavxd/libredesk/internal/user/models"
	realip "github.com/ferluci/fast-realip"
	"github.com/zerodha/fastglue"
)

const (
	guardIdentityKey = "auth.guard_identity"
	authMethodGuard  = "guard_identity"

	// guardSeenTTL is guard's absolute session lifetime: a login is recorded
	// once per guard session (per process).
	guardSeenTTL = 168 * time.Hour
	guardSeenMax = 10000
)

// guardRoles are the libredesk Zitadel project's role keys. Guard already
// requires one of them; checking again here keeps the desk closed if a guard
// rule is ever loosened. They only open the door: what an agent may do is
// still the role on their Libredesk account.
var guardRoles = []string{"admin", "agent"}

// guardIdentity verifies guard's identity header and resolves it to an agent.
type guardIdentity struct {
	verifier *edgeauth.Verifier
	// agentIDs maps a lower-cased email to the agent id it last resolved to,
	// so a request costs the agent cache lookup the session path costs.
	agentIDs sync.Map
	seen     seenSessions
}

// guardError is a refused guard identity. loginCode is the login page's
// error code for a page request (empty: answer with status instead).
type guardError struct {
	status    int
	etype     string
	message   string
	loginCode string
}

func (e guardError) Error() string { return e.message }

// toEnvelope is the error the API middlewares answer with.
func (e guardError) toEnvelope() error {
	return envelope.NewErrorWithCode(e.etype, e.status, e.message, nil)
}

// initGuardIdentity builds the verifier when auth.guard_identity is on. The
// JWKS URL and audiences come from PLATFORM_KIT_EDGEAUTH_JWKS_URL and
// PLATFORM_KIT_EDGEAUTH_AUDIENCES; guard is never contacted at start.
func initGuardIdentity() *guardIdentity {
	if !ko.Bool(guardIdentityKey) {
		return nil
	}
	cfg, err := edgeauth.ConfigFromEnv()
	if err != nil {
		log.Fatalf("error reading guard identity config: %v", err)
	}
	v, err := edgeauth.New(cfg)
	if err != nil {
		log.Fatalf("error initializing guard identity (set PLATFORM_KIT_EDGEAUTH_AUDIENCES): %v", err)
	}
	log.Printf("guard identity sign-in on for %s", strings.Join(cfg.Audiences, ", "))
	return newGuardIdentity(v)
}

func newGuardIdentity(v *edgeauth.Verifier) *guardIdentity {
	return &guardIdentity{verifier: v, seen: seenSessions{m: map[string]time.Time{}}}
}

// guardAgent returns the agent guard's identity header names. present is
// false when guard identity is off or the request carries no header; the
// caller then goes on to session auth. A refused identity is a guardError.
// The result is kept on the request, so page and API middlewares on the
// same request verify once.
func guardAgent(r *fastglue.Request, app *App) (user models.User, present bool, err error) {
	if app.guard == nil {
		return models.User{}, false, nil
	}
	token := string(r.RequestCtx.Request.Header.Peek(edgeauth.Header))
	if token == "" {
		return models.User{}, false, nil
	}
	if c, ok := r.RequestCtx.UserValue(guardResultKey).(guardResult); ok {
		return c.user, true, c.err
	}
	user, err = app.guard.agent(r, app, token)
	r.RequestCtx.SetUserValue(guardResultKey, guardResult{user: user, err: err})
	return user, true, err
}

const guardResultKey = "guard_identity_result"

type guardResult struct {
	user models.User
	err  error
}

func (g *guardIdentity) agent(r *fastglue.Request, app *App, token string) (models.User, error) {
	id, err := g.verifier.Verify(r.RequestCtx, token)
	if err != nil {
		path := string(r.RequestCtx.Path())
		if errors.Is(err, edgeauth.ErrUnavailable) {
			app.lo.Error("guard identity not checked: guard's keys unavailable", "path", path, "error", err)
			return models.User{}, guardError{status: http.StatusServiceUnavailable, etype: envelope.GeneralError, message: "identity keys unavailable"}
		}
		app.lo.Warn("guard identity refused", "path", path, "error", err)
		return models.User{}, guardError{status: http.StatusUnauthorized, etype: envelope.UnauthorizedError, message: app.i18n.T("auth.invalidOrExpiredSession")}
	}

	if !id.HasAnyRole(guardRoles...) {
		app.lo.Warn("guard identity without a libredesk role", "subject", id.Subject)
		return models.User{}, guardError{status: http.StatusForbidden, etype: envelope.PermissionError, message: app.i18n.T("auth.oidcAccessDenied"), loginCode: oidcErrAccessDenied}
	}

	noAccount := guardError{status: http.StatusForbidden, etype: envelope.PermissionError, message: app.i18n.T("auth.oidcNoAccount"), loginCode: oidcErrNoAccount}
	email := strings.ToLower(strings.TrimSpace(id.Email))
	if email == "" {
		app.lo.Warn("guard identity has no email", "subject", id.Subject)
		return models.User{}, noAccount
	}
	user, err := g.lookup(app, email)
	if err != nil {
		if e, ok := err.(envelope.Error); ok && e.ErrorType == envelope.NotFoundError {
			app.lo.Warn("no agent account matching guard identity email", "email", email)
			return models.User{}, noAccount
		}
		return models.User{}, guardError{status: http.StatusInternalServerError, etype: envelope.GeneralError, message: app.i18n.T("globals.messages.somethingWentWrong"), loginCode: oidcErrLoginFailed}
	}
	if !user.Enabled {
		app.lo.Warn("guard identity rejected for disabled account", "user_id", user.ID)
		return models.User{}, guardError{status: http.StatusForbidden, etype: envelope.PermissionError, message: app.i18n.T("user.accountDisabled"), loginCode: oidcErrAccountDisabled}
	}
	// Only agents sign in; GetAgent also resolves ai_assistant users.
	if user.Type != models.UserTypeAgent {
		app.lo.Warn("guard identity rejected for non-agent user", "user_id", user.ID)
		return models.User{}, noAccount
	}

	if g.seen.first(guardSessionKey(id, user.ID), time.Now()) {
		g.recordLogin(r, app, user)
	}
	return user, nil
}

// lookup resolves email to an agent through the agent cache, going to the
// database by email only on the first request or when the cached id no
// longer belongs to that email.
func (g *guardIdentity) lookup(app *App, email string) (models.User, error) {
	if id, ok := g.agentIDs.Load(email); ok {
		user, err := app.user.GetAgentCachedOrLoad(id.(int))
		if err == nil && strings.EqualFold(user.Email.String, email) {
			return user, nil
		}
		g.agentIDs.Delete(email)
	}
	user, err := app.user.GetAgent(0, email)
	if err != nil {
		return models.User{}, err
	}
	g.agentIDs.Store(email, user.ID)
	return user, nil
}

// recordLogin does what a login does, once per guard session.
func (g *guardIdentity) recordLogin(r *fastglue.Request, app *App, user models.User) {
	if err := app.user.UpdateLastLoginAt(user.ID); err != nil {
		app.lo.Error("error updating last login at for guard sign-in", "user_id", user.ID, "error", err)
	}
	app.user.InvalidateAgentCache(user.ID)
	if err := app.activityLog.Login(user.ID, user.Email.String, realip.FromRequest(r.RequestCtx)); err != nil {
		app.lo.Error("error creating login activity log", "error", err)
	}
	app.lo.Info("guard sign-in", "user_id", user.ID, "email", user.Email.String)
}

// guardSessionKey identifies the guard session (sid), or for a bearer
// identity, which has none, the Zitadel login.
func guardSessionKey(id edgeauth.Identity, userID int) string {
	sess := id.SessionID
	if sess == "" {
		sess = "sub:" + id.Subject + ":" + strconv.FormatInt(id.AuthTime.Unix(), 10)
	}
	return sess + ":" + strconv.Itoa(userID)
}

// seenSessions remembers which guard sessions were already recorded as a login.
type seenSessions struct {
	mu sync.Mutex
	m  map[string]time.Time
}

// first reports whether key is new (or older than guardSeenTTL) and marks it seen.
func (s *seenSessions) first(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if at, ok := s.m[key]; ok && now.Sub(at) < guardSeenTTL {
		return false
	}
	if len(s.m) >= guardSeenMax {
		for k, at := range s.m {
			if now.Sub(at) >= guardSeenTTL {
				delete(s.m, k)
			}
		}
		if len(s.m) >= guardSeenMax {
			s.m = map[string]time.Time{}
		}
	}
	s.m[key] = now
	return true
}

// guardPageFailure answers a page request whose guard identity was refused:
// to the login page with its error, or with the status for a token that is
// invalid or could not be checked. handled is false for any other error.
// On the login page itself (serve != nil) a request that already shows an
// error is served, so the redirect cannot loop.
func guardPageFailure(r *fastglue.Request, err error, next string, serve fastglue.FastRequestHandler) (handled bool, resp error) {
	var gerr guardError
	if !errors.As(err, &gerr) {
		return false, nil
	}
	if gerr.loginCode == "" {
		return true, r.SendErrorEnvelope(gerr.status, gerr.message, nil, fastglue.ErrorType(gerr.etype))
	}
	if serve != nil && len(r.RequestCtx.QueryArgs().Peek("error")) > 0 {
		return true, serve(r)
	}
	return true, redirectLoginError(r, gerr.loginCode, next)
}
