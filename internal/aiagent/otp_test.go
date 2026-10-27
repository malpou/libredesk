package aiagent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abhinavxd/libredesk/internal/kvstore"
	"github.com/abhinavxd/libredesk/internal/kvstore/kvtest"
	"github.com/zerodha/logf"
)

// otpTestEnv exposes the raw buckets and clock behind a test manager.
type otpTestEnv struct {
	t       *testing.T
	srv     *kvtest.Server
	clock   *kvtest.Clock
	pending *kvstore.Store
	state   *kvstore.Store
}

func newOTPTestManager(t *testing.T) (*Manager, *otpTestEnv) {
	t.Helper()
	srv := kvtest.Start(t)
	env := &otpTestEnv{t: t, srv: srv, clock: kvtest.NewClock(), pending: srv.Bucket("otp_pending"), state: srv.Bucket("otp_state")}
	env.pending.SetClock(env.clock.Now)
	env.state.SetClock(env.clock.Now)
	lo := logf.New(logf.Opts{})
	return &Manager{lo: &lo, otpPending: env.pending, otpState: env.state}, env
}

// set writes a raw value with no expiry, standing in for data written by an older build.
func (e *otpTestEnv) set(st *kvstore.Store, key, val string) {
	e.t.Helper()
	if err := st.Put(context.Background(), key, []byte(val), 0); err != nil {
		e.t.Fatal(err)
	}
}

func (e *otpTestEnv) get(st *kvstore.Store, key string) (string, bool) {
	v, err := st.Get(context.Background(), key)
	if errors.Is(err, kvstore.ErrNotFound) {
		return "", false
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return string(v.Value), true
}

func (e *otpTestEnv) exists(st *kvstore.Store, key string) bool {
	_, ok := e.get(st, key)
	return ok
}

// ttl returns how long the key has left on the test clock.
func (e *otpTestEnv) ttl(st *kvstore.Store, key string) time.Duration {
	e.t.Helper()
	v, err := st.Get(context.Background(), key)
	if err != nil {
		e.t.Fatal(err)
	}
	return v.Expires.Sub(e.clock.Now())
}

func TestIsConversationVerified(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const conv = "conv-a"

	if m.isConversationVerified(conv, "john@example.com") {
		t.Error("no verified key must mean unverified")
	}

	mr.set(mr.state, otpVerifiedKey(conv), "john@example.com")
	if !m.isConversationVerified(conv, "john@example.com") {
		t.Error("matching email must be verified")
	}
	if !m.isConversationVerified(conv, "  John@Example.COM  ") {
		t.Error("email comparison must be case- and whitespace-insensitive")
	}

	if m.isConversationVerified(conv, "victim@example.com") {
		t.Error("a rebound contact email must not stay verified")
	}
	if m.isConversationVerified(conv, "") {
		t.Error("empty contact email must be unverified")
	}
	if m.isConversationVerified("conv-b", "john@example.com") {
		t.Error("another conversation must not inherit the verified flag")
	}

	// Value written by a build that stored a bare flag instead of the email.
	mr.set(mr.state, otpVerifiedKey("conv-legacy"), "1")
	if m.isConversationVerified("conv-legacy", "john@example.com") {
		t.Error("legacy flag value must be unverified")
	}
}

func TestCheckPendingOTP(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const conv, email, code = "conv-a", "john@example.com", "123456"

	ok, err := m.checkPendingOTP(conv, code)
	if err != nil || ok {
		t.Errorf("check without a pending code = (%v, %v), want (false, nil)", ok, err)
	}

	if err := m.storePendingOTP(conv, code, "  John@Example.COM "); err != nil {
		t.Fatal(err)
	}
	ok, err = m.checkPendingOTP(conv, "999999")
	if err != nil || ok {
		t.Errorf("wrong code = (%v, %v), want (false, nil)", ok, err)
	}
	ok, err = m.checkPendingOTP(conv, code)
	if err != nil || !ok {
		t.Fatalf("correct code = (%v, %v), want (true, nil)", ok, err)
	}
	if got, _ := mr.get(mr.state, otpVerifiedKey(conv)); got != email {
		t.Errorf("verified value = %q, want the normalized attested email %q", got, email)
	}
	if mr.exists(mr.pending, otpPendingKey(conv)) {
		t.Error("pending key must be deleted on match")
	}
	if !m.isConversationVerified(conv, email) {
		t.Error("conversation must be verified after a correct code")
	}

	ok, err = m.checkPendingOTP(conv, code)
	if err != nil || ok {
		t.Errorf("code replay = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestCheckPendingOTPAttemptCap(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const conv, code = "conv-a", "123456"

	if err := m.storePendingOTP(conv, code, "john@example.com"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < otpMaxAttempts; i++ {
		if ok, _ := m.checkPendingOTP(conv, "000000"); ok {
			t.Fatal("wrong code must not verify")
		}
	}
	if mr.exists(mr.pending, otpPendingKey(conv)) {
		t.Error("pending key must be deleted at the attempt cap")
	}
	if ok, _ := m.checkPendingOTP(conv, code); ok {
		t.Error("correct code must not verify after the attempt cap")
	}
}

func TestCheckPendingOTPLegacyAndCorruptPayloads(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const conv = "conv-a"

	// Pending record from a build that stored no attested email.
	mr.set(mr.pending, otpPendingKey(conv), `{"code":"123456"}`)
	ok, err := m.checkPendingOTP(conv, "123456")
	if err != nil || ok {
		t.Errorf("legacy pending without email = (%v, %v), want (false, nil)", ok, err)
	}
	if mr.exists(mr.pending, otpPendingKey(conv)) {
		t.Error("legacy pending record must be deleted")
	}
	if mr.exists(mr.state, otpVerifiedKey(conv)) {
		t.Error("legacy pending record must never set the verified key")
	}

	mr.set(mr.pending, otpPendingKey(conv), "not-json")
	if ok, err := m.checkPendingOTP(conv, "123456"); err == nil || ok {
		t.Errorf("corrupt pending = (%v, %v), want (false, error)", ok, err)
	}
	if mr.exists(mr.pending, otpPendingKey(conv)) {
		t.Error("corrupt pending record must be deleted")
	}
}

func TestClearConversationVerified(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const conv, email = "conv-a", "john@example.com"

	mr.set(mr.state, otpVerifiedKey(conv), email)
	if err := m.storePendingOTP(conv, "123456", email); err != nil {
		t.Fatal(err)
	}
	if err := m.clearConversationVerified(conv); err != nil {
		t.Fatal(err)
	}
	if m.isConversationVerified(conv, email) {
		t.Error("conversation must be unverified after clear")
	}
	if mr.exists(mr.pending, otpPendingKey(conv)) {
		t.Error("pending key must be deleted on clear")
	}
}

// The cross-conversation rebind: verified on conversation A must not survive the shared
// contact's email being rewritten from a sibling conversation.
func TestVerifiedDoesNotSurviveEmailRebind(t *testing.T) {
	m, _ := newOTPTestManager(t)
	const convA, attacker, victim = "conv-a", "attacker@evil.com", "victim@example.com"

	if err := m.storePendingOTP(convA, "123456", attacker); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.checkPendingOTP(convA, "123456"); !ok {
		t.Fatal("verification must succeed for the attested email")
	}
	if !m.isConversationVerified(convA, attacker) {
		t.Fatal("conversation A must be verified for the attested email")
	}

	// Sibling conversation B rewrites the shared contact row; A's Redis keys are untouched.
	if m.isConversationVerified(convA, victim) {
		t.Error("conversation A must not stay verified once the contact email is rebound")
	}
}

func TestVerifiedTTL(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const conv, email = "conv-a", "john@example.com"

	if err := m.storePendingOTP(conv, "123456", email); err != nil {
		t.Fatal(err)
	}
	if got := mr.ttl(mr.pending, otpPendingKey(conv)); got != otpPendingTTL {
		t.Errorf("pending TTL = %v, want %v", got, otpPendingTTL)
	}
	if ok, _ := m.checkPendingOTP(conv, "123456"); !ok {
		t.Fatal("verification must succeed")
	}
	if got := mr.ttl(mr.state, otpVerifiedKey(conv)); got != otpVerifiedTTL {
		t.Errorf("verified TTL = %v, want %v", got, otpVerifiedTTL)
	}
	mr.clock.Advance(otpVerifiedTTL + time.Second)
	if m.isConversationVerified(conv, email) {
		t.Error("conversation must be unverified after the verified TTL")
	}
}

func TestWrongAttemptKeepsPendingTTL(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const conv = "conv-a"

	if err := m.storePendingOTP(conv, "123456", "john@example.com"); err != nil {
		t.Fatal(err)
	}
	mr.clock.Advance(otpPendingTTL / 2)
	if ok, _ := m.checkPendingOTP(conv, "000000"); ok {
		t.Fatal("wrong code must not verify")
	}
	if got := mr.ttl(mr.pending, otpPendingKey(conv)); got != otpPendingTTL/2 {
		t.Errorf("pending TTL after a wrong attempt = %v, want %v", got, otpPendingTTL/2)
	}
}

// Guards against the store failing open on connection errors.
func TestVerifiedFailsClosedOnStoreError(t *testing.T) {
	m, mr := newOTPTestManager(t)
	mr.set(mr.state, otpVerifiedKey("conv-a"), "john@example.com")
	mr.srv.Shutdown()
	if m.isConversationVerified("conv-a", "john@example.com") {
		t.Error("a store error must mean unverified")
	}
}

// concurrencyRounds repeats each race on a fresh conversation so a lost update shows up reliably.
const concurrencyRounds = 25

// runConcurrently starts n calls of fn at once and waits for them.
func runConcurrently(n int, fn func(i int)) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			fn(i)
		}()
	}
	close(start)
	wg.Wait()
}

// Parallel wrong guesses must each burn one attempt: with the cap at otpMaxAttempts, no more
// than that many guesses may be evaluated against the code, however many arrive at once.
func TestCheckPendingOTPAttemptCapUnderConcurrency(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const code = "123456"

	for round := range concurrencyRounds {
		conv := fmt.Sprintf("conv-%d", round)
		if err := m.storePendingOTP(conv, code, "john@example.com"); err != nil {
			t.Fatal(err)
		}
		runConcurrently(20, func(int) {
			if ok, err := m.checkPendingOTP(conv, "000000"); ok || err != nil {
				t.Errorf("wrong guess = (%v, %v), want (false, nil)", ok, err)
			}
		})
		if mr.exists(mr.pending, otpPendingKey(conv)) {
			t.Fatalf("round %d: pending code survived more wrong guesses than the attempt cap", round)
		}
		if ok, _ := m.checkPendingOTP(conv, code); ok {
			t.Fatalf("round %d: correct code verified after the attempt cap was spent concurrently", round)
		}
	}
}

// A correct code sent by many requests at once must verify exactly one of them.
func TestCheckPendingOTPSingleUseUnderConcurrency(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const email, code = "john@example.com", "123456"

	for round := range concurrencyRounds {
		conv := fmt.Sprintf("conv-%d", round)
		if err := m.storePendingOTP(conv, code, email); err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int32
		runConcurrently(20, func(int) {
			ok, err := m.checkPendingOTP(conv, code)
			if err != nil {
				t.Errorf("check: %v", err)
			}
			if ok {
				wins.Add(1)
			}
		})
		if got := wins.Load(); got != 1 {
			t.Fatalf("round %d: correct code verified %d requests, want exactly 1", round, got)
		}
		if mr.exists(mr.pending, otpPendingKey(conv)) {
			t.Fatalf("round %d: pending key must be consumed by the winning request", round)
		}
		if !m.isConversationVerified(conv, email) {
			t.Fatalf("round %d: conversation must be verified", round)
		}
	}
}

func TestOTPSendCap(t *testing.T) {
	m, mr := newOTPTestManager(t)
	const conv = "conv-a"

	for i := range otpMaxSends {
		if capped, err := m.otpSendCapReached(conv, "john+otp@example.com"); err != nil || capped {
			t.Fatalf("send %d: capped = (%v, %v), want (false, nil)", i, capped, err)
		}
		if err := m.incrOTPSends(conv, "John+OTP@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if capped, _ := m.otpSendCapReached(conv, "john+otp@example.com"); !capped {
		t.Error("per-address cap must be reached")
	}
	if capped, _ := m.otpSendCapReached(conv, "other@example.com"); capped {
		t.Error("a fresh address must have its own budget while the conversation budget lasts")
	}

	// The budget window starts at the first send and later sends must not extend it.
	mr.clock.Advance(otpVerifiedTTL - time.Minute)
	if err := m.incrOTPSends(conv, "other@example.com"); err != nil {
		t.Fatal(err)
	}
	mr.clock.Advance(2 * time.Minute)
	if capped, _ := m.otpSendCapReached(conv, "john+otp@example.com"); capped {
		t.Error("the per-address budget must reset once its window ends")
	}
}

func TestNormalizeOTPEmail(t *testing.T) {
	cases := map[string]string{
		"  John@Example.COM ": "john@example.com",
		"":                    "",
		"a@b.c":               "a@b.c",
	}
	for in, want := range cases {
		if got := normalizeOTPEmail(in); got != want {
			t.Errorf("normalizeOTPEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
