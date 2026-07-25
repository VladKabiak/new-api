package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestNormalizeAndHashTokenKey(t *testing.T) {
	rawKey := strings.Repeat("a", 40) + "wxyz1234"
	expected := sha256.Sum256([]byte(rawKey))

	tests := []struct {
		name      string
		presented string
		wantHash  string
	}{
		{"canonical key", rawKey, hex.EncodeToString(expected[:])},
		{"sk- prefix", "sk-" + rawKey, hex.EncodeToString(expected[:])},
		{"surrounding whitespace", "  sk-" + rawKey + "  ", hex.EncodeToString(expected[:])},
		{"channel selection suffix", "sk-" + rawKey + "-42", hex.EncodeToString(expected[:])},
		{"empty key", "", ""},
		{"prefix only", "sk-", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantHash, HashTokenKey(tc.presented))
		})
	}

	assert.NotEqual(t, HashTokenKey(rawKey), HashTokenKey(rawKey[:len(rawKey)-1]+"Z"),
		"a different key must not collide")
	assert.Equal(t, NormalizeTokenKey(rawKey), NormalizeTokenKey(NormalizeTokenKey("sk-"+rawKey)),
		"normalization must be idempotent so create and validate agree")
}

func TestBuildTokenKeyPrefixKeepsOnlyTheEdges(t *testing.T) {
	rawKey := "abcd" + strings.Repeat("m", 40) + "wxyz"

	prefix := BuildTokenKeyPrefix("sk-" + rawKey)
	assert.Equal(t, "abcdwxyz", prefix, "fragment keeps only the first and last four characters")
	assert.NotContains(t, prefix, rawKey[4:len(rawKey)-4],
		"the stored fragment must not expose the middle of the key")
}

// A short key cannot be fragmented without persisting most of itself, which would
// leave a usable key in a column that is supposed to be non-sensitive.
func TestBuildTokenKeyPrefixKeepsNothingForShortKeys(t *testing.T) {
	for _, shortKey := range []string{"abc", "abcd1234", strings.Repeat("s", minKeyLenForPrefix-1)} {
		t.Run(shortKey[:min(len(shortKey), 8)], func(t *testing.T) {
			prefix := BuildTokenKeyPrefix(shortKey)
			assert.Empty(t, prefix, "no fragment may be stored for a short key")
		})
	}
}

func TestValidateUserTokenAuthenticatesByHashOnly(t *testing.T) {
	truncateTables(t)

	rawKey := strings.Repeat("k", 40) + "abcd1234"
	token := Token{
		UserId:         41,
		Name:           "hash-auth",
		KeyHash:        HashTokenKey(rawKey),
		KeyPrefix:      BuildTokenKeyPrefix(rawKey),
		Status:         common.TokenStatusEnabled,
		ExpiredTime:    -1,
		UnlimitedQuota: true,
	}
	require.NoError(t, DB.Create(&token).Error)

	// No cleartext is persisted, so the row cannot be found by the key itself.
	var plaintextRows int64
	require.NoError(t, DB.Table("tokens").Where("key_hash = ?", rawKey).Count(&plaintextRows).Error)
	assert.Zero(t, plaintextRows)

	for _, presented := range []string{rawKey, "sk-" + rawKey} {
		found, err := ValidateUserToken(presented)
		require.NoError(t, err, "key must authenticate when presented as %q", presented)
		require.NotNil(t, found)
		assert.Equal(t, token.Id, found.Id)
	}

	_, err := ValidateUserToken(strings.Repeat("k", 40) + "abcd9999")
	assert.ErrorIs(t, err, ErrTokenInvalid, "a key whose hash matches nothing is rejected")

	_, err = ValidateUserToken("")
	assert.ErrorIs(t, err, ErrTokenNotProvided)
}

func TestGetTokenByKeyRejectsHashMismatch(t *testing.T) {
	truncateTables(t)

	rawKey := strings.Repeat("c", 40) + "0000ffff"
	require.NoError(t, DB.Create(&Token{
		UserId:         42,
		Name:           "exact-hash",
		KeyHash:        HashTokenKey(rawKey),
		KeyPrefix:      BuildTokenKeyPrefix(rawKey),
		Status:         common.TokenStatusEnabled,
		ExpiredTime:    -1,
		UnlimitedQuota: true,
	}).Error)

	found, err := GetTokenByKey(HashTokenKey(rawKey), true)
	require.NoError(t, err)
	require.NotNil(t, found)

	// An upper-cased hash is a different value; a case-insensitive collation must
	// not be allowed to authenticate it.
	_, err = GetTokenByKey(strings.ToUpper(HashTokenKey(rawKey)), true)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)

	_, err = GetTokenByKey("", true)
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}
