package common

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// A pending registration lives in memory only: the account appears in the
// database when the emailed code is entered, so an unconfirmed address never
// occupies a username and the password is never stored unverified.
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

var RegistrationValidMinutes = 30

var pendingRegistrationMutex sync.Mutex
var pendingRegistrations = make(map[string]PendingRegistration)

// GenerateEmailCode returns the six-digit code sent in confirmation letters.
func GenerateEmailCode() string {
	limit := big.NewInt(1000000)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	}
	return fmt.Sprintf("%06d", value.Int64())
}

func RegisterPendingRegistration(email string, password string, code string) {
	pendingRegistrationMutex.Lock()
	defer pendingRegistrationMutex.Unlock()
	removeExpiredRegistrations()
	pendingRegistrations[email] = PendingRegistration{
		Email:    email,
		Password: password,
		code:     code,
		created:  time.Now(),
	}
}

// TakePendingRegistration consumes the pending registration when the code
// matches. A wrong code spends one attempt and drops the registration once the
// budget runs out, which forces the visitor to request a fresh code.
func TakePendingRegistration(email string, code string) (PendingRegistration, bool) {
	pendingRegistrationMutex.Lock()
	defer pendingRegistrationMutex.Unlock()
	removeExpiredRegistrations()
	pending, okay := pendingRegistrations[email]
	if !okay {
		return PendingRegistration{}, false
	}
	if subtle.ConstantTimeCompare([]byte(pending.code), []byte(code)) != 1 {
		pending.attempts++
		if pending.attempts >= EmailCodeMaxAttempts {
			delete(pendingRegistrations, email)
		} else {
			pendingRegistrations[email] = pending
		}
		return PendingRegistration{}, false
	}
	delete(pendingRegistrations, email)
	return pending, true
}

// no lock inside, so the caller must lock pendingRegistrationMutex before calling!
func removeExpiredRegistrations() {
	now := time.Now()
	for email, pending := range pendingRegistrations {
		if now.Sub(pending.created) >= time.Duration(RegistrationValidMinutes)*time.Minute {
			delete(pendingRegistrations, email)
		}
	}
}

var codeAttemptMutex sync.Mutex
var codeAttempts = make(map[string]int)

// SpendCodeAttempt reports whether another code may be checked for the key and
// counts this one. It guards the codes that live in the shared verification
// map, which has no attempt budget of its own.
func SpendCodeAttempt(key string) bool {
	codeAttemptMutex.Lock()
	defer codeAttemptMutex.Unlock()
	if codeAttempts[key] >= EmailCodeMaxAttempts {
		return false
	}
	codeAttempts[key]++
	return true
}

func ClearCodeAttempts(key string) {
	codeAttemptMutex.Lock()
	defer codeAttemptMutex.Unlock()
	delete(codeAttempts, key)
}
