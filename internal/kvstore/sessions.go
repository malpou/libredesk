package kvstore

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"
)

// Session store errors. The codes match the ones simplesessions maps to its own errors.
var (
	ErrInvalidSession = &SessionErr{code: 1, msg: "invalid session"}
	ErrNil            = &SessionErr{code: 2, msg: "nil returned"}
	ErrAssertType     = &SessionErr{code: 3, msg: "assertion failed"}
)

// SessionErr is a simplesessions-compatible store error.
type SessionErr struct {
	code int
	msg  string
}

func (e *SessionErr) Error() string { return e.msg }

// Code returns the simplesessions error code.
func (e *SessionErr) Code() int { return e.code }

// SessionStore is a simplesessions.Store keeping each session as one JSON object of string
// fields. Sessions expire a fixed TTL after they are created; writes keep that expiry, so a
// session ends at the same time however active it is.
type SessionStore struct {
	st  *Store
	ttl time.Duration
}

// NewSessionStore returns a session store over st whose sessions live for ttl.
func NewSessionStore(st *Store, ttl time.Duration) *SessionStore {
	return &SessionStore{st: st, ttl: ttl}
}

// Create stores a new empty session.
func (s *SessionStore) Create(id string) error {
	_, err := s.st.Create(context.Background(), sessionKey(id), []byte("{}"), s.ttl)
	return err
}

// Get returns one field, or nil if the field is not set.
func (s *SessionStore) Get(id, key string) (interface{}, error) {
	vals, _, err := s.load(id)
	if err != nil {
		return nil, err
	}
	if v, ok := vals[key]; ok {
		return v, nil
	}
	return nil, nil
}

// GetMulti returns the given fields, with nil for those that are not set.
func (s *SessionStore) GetMulti(id string, keys ...string) (map[string]interface{}, error) {
	vals, _, err := s.load(id)
	if err != nil {
		return nil, err
	}
	out := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		if v, ok := vals[k]; ok {
			out[k] = v
		} else {
			out[k] = nil
		}
	}
	return out, nil
}

// GetAll returns every field; a missing session yields an empty map, as with the Redis store.
func (s *SessionStore) GetAll(id string) (map[string]interface{}, error) {
	vals, _, err := s.load(id)
	if errors.Is(err, ErrInvalidSession) {
		return map[string]interface{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make(map[string]interface{}, len(vals))
	for k, v := range vals {
		out[k] = v
	}
	return out, nil
}

// Set sets one field.
func (s *SessionStore) Set(id, key string, val interface{}) error {
	return s.SetMulti(id, map[string]interface{}{key: val})
}

// SetMulti sets several fields in one compare-and-swap write. Writing to a session that does
// not exist (or has expired) starts it afresh with the full TTL.
func (s *SessionStore) SetMulti(id string, data map[string]interface{}) error {
	fields := make(map[string]string, len(data))
	for k, v := range data {
		str, err := sessionValue(v)
		if err != nil {
			return fmt.Errorf("session field %q: %w", k, err)
		}
		fields[k] = str
	}
	return s.mutate(id, func(vals map[string]string) {
		for k, v := range fields {
			vals[k] = v
		}
	})
}

// Delete removes fields from the session.
func (s *SessionStore) Delete(id string, keys ...string) error {
	return s.mutate(id, func(vals map[string]string) {
		for _, k := range keys {
			delete(vals, k)
		}
	})
}

// Clear empties the session and restarts its TTL.
func (s *SessionStore) Clear(id string) error {
	return s.st.Put(context.Background(), sessionKey(id), []byte("{}"), s.ttl)
}

// Destroy deletes the session.
func (s *SessionStore) Destroy(id string) error {
	return s.st.Delete(context.Background(), sessionKey(id))
}

func (s *SessionStore) load(id string) (map[string]string, Entry, error) {
	e, err := s.st.Get(context.Background(), sessionKey(id))
	if errors.Is(err, ErrNotFound) {
		return nil, Entry{}, ErrInvalidSession
	}
	if err != nil {
		return nil, Entry{}, err
	}
	var vals map[string]string
	if err := json.Unmarshal(e.Value, &vals); err != nil {
		return nil, Entry{}, fmt.Errorf("decoding session: %w", err)
	}
	return vals, e, nil
}

func (s *SessionStore) mutate(id string, fn func(map[string]string)) error {
	return s.st.Mutate(context.Background(), sessionKey(id), func(cur Entry, found bool) ([]byte, time.Time, error) {
		vals := map[string]string{}
		expires := s.st.ExpiresIn(s.ttl)
		if found {
			if err := json.Unmarshal(cur.Value, &vals); err != nil {
				return nil, time.Time{}, fmt.Errorf("decoding session: %w", err)
			}
			expires = cur.Expires
		}
		fn(vals)
		b, err := json.Marshal(vals)
		return b, expires, err
	})
}

func sessionKey(id string) string { return Key(id) }

// sessionValue formats a value the way go-redis writes hash fields, so the type helpers
// below read back what the Redis store used to return.
func sessionValue(v interface{}) (string, error) {
	switch v := v.(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	case int:
		return strconv.Itoa(v), nil
	case int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v), nil
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case bool:
		if v {
			return "1", nil
		}
		return "0", nil
	case encoding.TextMarshaler:
		b, err := v.MarshalText()
		return string(b), err
	}
	return "", fmt.Errorf("unsupported type %T", v)
}

// Int converts a stored value to int.
func (s *SessionStore) Int(r interface{}, err error) (int, error) {
	n, err := s.Int64(r, err)
	if err != nil {
		return 0, err
	}
	if x := int(n); int64(x) == n {
		return x, nil
	}
	return 0, ErrAssertType
}

// Int64 converts a stored value to int64.
func (s *SessionStore) Int64(r interface{}, err error) (int64, error) {
	str, err := s.String(r, err)
	if err != nil {
		return 0, err
	}
	n, perr := strconv.ParseInt(str, 10, 64)
	if perr != nil {
		return 0, ErrAssertType
	}
	return n, nil
}

// UInt64 converts a stored value to uint64.
func (s *SessionStore) UInt64(r interface{}, err error) (uint64, error) {
	str, err := s.String(r, err)
	if err != nil {
		return 0, err
	}
	n, perr := strconv.ParseUint(str, 10, 64)
	if perr != nil {
		return 0, ErrAssertType
	}
	return n, nil
}

// Float64 converts a stored value to float64.
func (s *SessionStore) Float64(r interface{}, err error) (float64, error) {
	str, err := s.String(r, err)
	if err != nil {
		return 0, err
	}
	n, perr := strconv.ParseFloat(str, 64)
	if perr != nil {
		return 0, ErrAssertType
	}
	return n, nil
}

// String converts a stored value to string.
func (s *SessionStore) String(r interface{}, err error) (string, error) {
	if err != nil {
		return "", err
	}
	switch r := r.(type) {
	case string:
		return r, nil
	case []byte:
		return string(r), nil
	case nil:
		return "", ErrNil
	case error:
		return "", r
	}
	return "", ErrAssertType
}

// Bytes converts a stored value to bytes.
func (s *SessionStore) Bytes(r interface{}, err error) ([]byte, error) {
	str, err := s.String(r, err)
	if err != nil {
		return nil, err
	}
	return []byte(str), nil
}

// Bool converts a stored value to bool.
func (s *SessionStore) Bool(r interface{}, err error) (bool, error) {
	str, err := s.String(r, err)
	if err != nil {
		return false, err
	}
	b, perr := strconv.ParseBool(str)
	if perr != nil {
		return false, ErrAssertType
	}
	return b, nil
}

// userSessionsKey holds the IDs of a user's sessions, so all of them can be ended at once.
// Session keys are bare IDs, so the dotted index key can never collide with one.
func userSessionsKey(userID int) string { return Key("user_sessions", strconv.Itoa(userID)) }

// IndexUserSession adds a session to the user's index. The index lives as long as the user's
// newest session: each login extends it to a full TTL and never shortens it.
func (s *SessionStore) IndexUserSession(ctx context.Context, userID int, sessID string) error {
	return s.st.Mutate(ctx, userSessionsKey(userID), func(cur Entry, found bool) ([]byte, time.Time, error) {
		ids, err := decodeIDs(cur, found)
		if err != nil {
			return nil, time.Time{}, err
		}
		if !slices.Contains(ids, sessID) {
			ids = append(ids, sessID)
		}
		expires := s.st.ExpiresIn(s.ttl)
		if found && (cur.Expires.IsZero() || cur.Expires.After(expires)) {
			expires = cur.Expires
		}
		b, err := json.Marshal(ids)
		return b, expires, err
	})
}

// UnindexUserSession removes a session from the user's index, deleting the index once empty.
func (s *SessionStore) UnindexUserSession(ctx context.Context, userID int, sessID string) error {
	return s.st.Mutate(ctx, userSessionsKey(userID), func(cur Entry, found bool) ([]byte, time.Time, error) {
		if !found {
			return nil, time.Time{}, nil
		}
		ids, err := decodeIDs(cur, found)
		if err != nil {
			return nil, time.Time{}, err
		}
		ids = slices.DeleteFunc(ids, func(id string) bool { return id == sessID })
		if len(ids) == 0 {
			return nil, time.Time{}, nil
		}
		b, err := json.Marshal(ids)
		return b, cur.Expires, err
	})
}

// DestroyUserSessions deletes every indexed session of the user, then the index itself.
func (s *SessionStore) DestroyUserSessions(ctx context.Context, userID int) error {
	key := userSessionsKey(userID)
	e, err := s.st.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("fetching user sessions: %w", err)
	}
	ids, err := decodeIDs(e, true)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(ids)+1)
	for _, id := range ids {
		keys = append(keys, sessionKey(id))
	}
	keys = append(keys, key)
	if err := s.st.Delete(ctx, keys...); err != nil {
		return fmt.Errorf("destroying user sessions: %w", err)
	}
	return nil
}

func decodeIDs(e Entry, found bool) ([]string, error) {
	if !found {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal(e.Value, &ids); err != nil {
		return nil, fmt.Errorf("decoding user session index: %w", err)
	}
	return ids, nil
}
