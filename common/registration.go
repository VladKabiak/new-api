package common

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// A pending registration lives in memory only: the account appears in the
// database when the emailed code is entered, so an unconfirmed address never
// occupies a username and the password is never stored unverified. It is keyed
// by a handle the browser carries rather than by the address, so a second
// request for the same address cannot replace the password sitting behind a
// code that was already mailed to someone else.
type PendingRegistration struct {
	Email    string
	Password string
	code     string
	created  time.Time
	attempts int
}

// A six-digit code is short enough to retype and short enough to guess, so it
// only stays safe behind a budget of attempts.
const EmailCodeMaxAttempts = 5

// Running the budget out locks the address for this long instead of dropping
// the code, so a stranger cannot invalidate a code mailed to someone else.
const EmailCodeLockMinutes = 15

var RegistrationValidMinutes = 30

var pendingRegistrationMutex sync.Mutex
var pendingRegistrations = make(map[string]PendingRegistration)

// GenerateEmailCode returns the six-digit code sent in confirmation letters.
func GenerateEmailCode() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

// NewRegistrationHandle returns the opaque key a pending registration is
// stored under and the browser sends back with the code.
func NewRegistrationHandle() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func RegisterPendingRegistration(handle string, email string, password string, code string) {
	pendingRegistrationMutex.Lock()
	defer pendingRegistrationMutex.Unlock()
	removeExpiredRegistrations()
	pendingRegistrations[handle] = PendingRegistration{
		Email:    email,
		Password: password,
		code:     code,
		created:  time.Now(),
	}
}

// TakePendingRegistration consumes the pending registration when the code
// matches. A wrong code spends one attempt and drops the registration once the
// budget runs out, which forces the visitor to request a fresh code.
func TakePendingRegistration(handle string, code string) (PendingRegistration, bool) {
	pendingRegistrationMutex.Lock()
	defer pendingRegistrationMutex.Unlock()
	removeExpiredRegistrations()
	pending, okay := pendingRegistrations[handle]
	if !okay {
		return PendingRegistration{}, false
	}
	if subtle.ConstantTimeCompare([]byte(pending.code), []byte(code)) != 1 {
		pending.attempts++
		if pending.attempts >= EmailCodeMaxAttempts {
			delete(pendingRegistrations, handle)
		} else {
			pendingRegistrations[handle] = pending
		}
		return PendingRegistration{}, false
	}
	delete(pendingRegistrations, handle)
	return pending, true
}

// no lock inside, so the caller must lock pendingRegistrationMutex before calling!
func removeExpiredRegistrations() {
	now := time.Now()
	for handle, pending := range pendingRegistrations {
		if now.Sub(pending.created) >= time.Duration(RegistrationValidMinutes)*time.Minute {
			delete(pendingRegistrations, handle)
		}
	}
}

type codeAttempt struct {
	count       int
	lockedUntil time.Time
	touched     time.Time
}

var codeAttemptMutex sync.Mutex
var codeAttempts = make(map[string]codeAttempt)

// SpendCodeAttempt reports whether another code may be checked for the key and
// counts this one. It guards the codes that live in the shared verification
// map, which has no attempt budget of its own. Spending the last attempt locks
// the key for EmailCodeLockMinutes; the lock outlives a resend, so requesting
// a new code does not hand the caller a fresh budget.
func SpendCodeAttempt(key string) bool {
	codeAttemptMutex.Lock()
	defer codeAttemptMutex.Unlock()
	removeExpiredAttempts()
	now := time.Now()
	attempt := codeAttempts[key]
	if !attempt.lockedUntil.IsZero() && now.Before(attempt.lockedUntil) {
		return false
	}
	attempt.count++
	attempt.touched = now
	if attempt.count >= EmailCodeMaxAttempts {
		attempt.count = 0
		attempt.lockedUntil = now.Add(time.Duration(EmailCodeLockMinutes) * time.Minute)
	}
	codeAttempts[key] = attempt
	return true
}

func ClearCodeAttempts(key string) {
	codeAttemptMutex.Lock()
	defer codeAttemptMutex.Unlock()
	removeExpiredAttempts()
	delete(codeAttempts, key)
}

// no lock inside, so the caller must lock codeAttemptMutex before calling!
func removeExpiredAttempts() {
	now := time.Now()
	window := time.Duration(EmailCodeLockMinutes) * time.Minute
	for key, attempt := range codeAttempts {
		if !attempt.lockedUntil.IsZero() && now.Before(attempt.lockedUntil) {
			continue
		}
		if now.Sub(attempt.touched) >= window {
			delete(codeAttempts, key)
		}
	}
}
