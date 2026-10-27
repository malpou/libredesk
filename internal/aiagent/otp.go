package aiagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/abhinavxd/libredesk/internal/kvstore"
	"github.com/abhinavxd/libredesk/internal/stringutil"
)

const (
	otpPendingTTL  = 10 * time.Minute
	otpVerifiedTTL = 30 * time.Minute

	otpMaxAttempts = 3
	// otpMaxSends is the per-address nag limit; otpMaxConvSends bounds total outbound mail for the
	// conversation, since set_contact_email lets the customer switch to a fresh address at will.
	otpMaxSends     = 3
	otpMaxConvSends = 6
)

// pendingOTP is the JSON stored at otpPendingKeyPrefix while a code awaits entry.
type pendingOTP struct {
	Code     string `json:"code"`
	Email    string `json:"email"`
	Attempts int    `json:"attempts"`
}

// Pending codes live in the otp pending bucket; verified emails and send counters in the otp
// state bucket.
func otpPendingKey(convUUID string) string  { return kvstore.Key("pending", convUUID) }
func otpVerifiedKey(convUUID string) string { return kvstore.Key("verified", convUUID) }

func normalizeOTPEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// otpSendsKey scopes the send budget to one address so correcting a mistyped email gets a fresh one.
func otpSendsKey(convUUID, email string) string {
	return kvstore.Key("sends", convUUID, normalizeOTPEmail(email))
}

func otpConvSendsKey(convUUID string) string { return kvstore.Key("sends", convUUID) }

// isConversationVerified holds the invariant "verified == the contact's current email is the one
// proven by OTP": the verified value stores the attested address, and a contact email rebound
// after verification (from this or any sibling conversation) no longer matches.
func (m *Manager) isConversationVerified(convUUID, contactEmail string) bool {
	email := normalizeOTPEmail(contactEmail)
	if email == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	e, err := m.otpState.Get(ctx, otpVerifiedKey(convUUID))
	if err != nil {
		if !errors.Is(err, kvstore.ErrNotFound) {
			m.lo.Error("error reading otp verified key", "conversation_uuid", convUUID, "error", err)
		}
		return false
	}
	return string(e.Value) == email
}

// clearConversationVerified drops the verified flag and any pending code so a changed email must be
// verified afresh.
func (m *Manager) clearConversationVerified(convUUID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.otpState.Delete(ctx, otpVerifiedKey(convUUID)); err != nil {
		return err
	}
	return m.otpPending.Delete(ctx, otpPendingKey(convUUID))
}

// otpSendCapReached reports whether this address or the conversation as a whole is out of sends.
func (m *Manager) otpSendCapReached(convUUID, email string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	perAddress, err := m.otpCount(ctx, otpSendsKey(convUUID, email))
	if err != nil {
		return false, err
	}
	perConv, err := m.otpCount(ctx, otpConvSendsKey(convUUID))
	if err != nil {
		return false, err
	}
	return perAddress >= otpMaxSends || perConv >= otpMaxConvSends, nil
}

// incrOTPSends records a code that was actually emailed against both the address and conversation
// budgets. Each budget's window starts at its first send.
func (m *Manager) incrOTPSends(convUUID, email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := m.otpState.Incr(ctx, otpSendsKey(convUUID, email), otpVerifiedTTL); err != nil {
		return err
	}
	_, err := m.otpState.Incr(ctx, otpConvSendsKey(convUUID), otpVerifiedTTL)
	return err
}

func (m *Manager) storePendingOTP(convUUID, code, email string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := json.Marshal(pendingOTP{Code: code, Email: normalizeOTPEmail(email)})
	if err != nil {
		return err
	}
	return m.otpPending.Put(ctx, otpPendingKey(convUUID), b, otpPendingTTL)
}

// checkPendingOTP matches code against the pending code and, on match, marks the conversation
// verified. Every outcome is a compare-and-swap on the pending revision that was read, so
// concurrent checks each consume exactly one attempt and only one of them can win a match.
// The pending key is cleared on match, corrupt data, the attempt cap or a legacy record.
func (m *Manager) checkPendingOTP(convUUID, code string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	key := otpPendingKey(convUUID)

	for {
		e, err := m.otpPending.Get(ctx, key)
		if errors.Is(err, kvstore.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		var p pendingOTP
		if err := json.Unmarshal(e.Value, &p); err != nil {
			if err := m.otpPending.DeleteRevision(ctx, key, e.Revision); errors.Is(err, kvstore.ErrConflict) {
				continue
			}
			return false, fmt.Errorf("corrupt pending otp for conversation %s", convUUID)
		}
		if p.Email == "" {
			if err := m.otpPending.DeleteRevision(ctx, key, e.Revision); errors.Is(err, kvstore.ErrConflict) {
				continue
			} else if err != nil {
				return false, err
			}
			return false, nil
		}

		if p.Code == code {
			// Consuming the pending revision is what makes the code single-use.
			if err := m.otpPending.DeleteRevision(ctx, key, e.Revision); errors.Is(err, kvstore.ErrConflict) {
				continue
			} else if err != nil {
				return false, err
			}
			if err := m.otpState.Put(ctx, otpVerifiedKey(convUUID), []byte(p.Email), otpVerifiedTTL); err != nil {
				return false, err
			}
			return true, nil
		}

		p.Attempts++
		if p.Attempts >= otpMaxAttempts {
			err = m.otpPending.DeleteRevision(ctx, key, e.Revision)
		} else {
			var b []byte
			if b, err = json.Marshal(p); err != nil {
				return false, err
			}
			// Keep the original expiry: a wrong attempt must not extend the code's lifetime.
			_, err = m.otpPending.Update(ctx, key, b, e.Expires, e.Revision)
		}
		if errors.Is(err, kvstore.ErrConflict) {
			continue
		}
		if err != nil {
			return false, err
		}
		return false, nil
	}
}

// generateOTP returns a random 6-digit numeric code.
func generateOTP() (string, error) {
	return stringutil.RandomNumeric(6)
}

// otpCount reads one send counter, treating a missing or unparseable value as zero.
func (m *Manager) otpCount(ctx context.Context, key string) (int64, error) {
	e, err := m.otpState.Get(ctx, key)
	if errors.Is(err, kvstore.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(string(e.Value), 10, 64)
	if err != nil {
		return 0, nil
	}
	return n, nil
}
