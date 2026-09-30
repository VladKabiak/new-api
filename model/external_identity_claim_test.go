package model

import (
	"fmt"
	"testing"

	"github.com/QuantumNous/new-api/common"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestExternalIdentityClaimEnforcesSingleOwnerAtomically(t *testing.T) {
	truncateTables(t)

	first := User{Username: "telegram-owner-one", Password: "password", AffCode: "telegram-owner-one"}
	second := User{Username: "telegram-owner-two", Password: "password", AffCode: "telegram-owner-two"}
	require.NoError(t, DB.Create(&first).Error)
	require.NoError(t, DB.Create(&second).Error)

	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, "telegram-123", first.Id)
	}))
	err := DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, "telegram-123", second.Id)
	})
	assert.ErrorIs(t, err, ErrExternalIdentityAlreadyClaimed)

	err = DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, "telegram-456", first.Id)
	})
	assert.ErrorIs(t, err, ErrExternalIdentityAlreadyClaimed)

	var claims []ExternalIdentityClaim
	require.NoError(t, DB.Find(&claims).Error)
	require.Len(t, claims, 1)
	assert.Equal(t, first.Id, claims[0].UserId)
	assert.Equal(t, "telegram-123", claims[0].Subject)

	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ReleaseExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, first.Id)
	}))
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, "telegram-123", second.Id)
	}))
}

func TestAdminClearBindingReleasesIdentityClaim(t *testing.T) {
	truncateTables(t)

	user := User{Username: "telegram-unbind", TelegramId: "telegram-unbind-id"}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, user.TelegramId, user.Id)
	}))

	require.NoError(t, user.ClearBinding(ExternalIdentityProviderTelegram))
	assert.Empty(t, user.TelegramId)

	var count int64
	require.NoError(t, DB.Model(&ExternalIdentityClaim{}).Where("user_id = ?", user.Id).Count(&count).Error)
	assert.Zero(t, count)
}

func TestInitializeExternalIdentityClaimsIsIdempotent(t *testing.T) {
	truncateTables(t)

	user := User{Username: "telegram-legacy", Password: "password", TelegramId: "telegram-legacy-id"}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, InitializeExternalIdentityClaims())
	require.NoError(t, InitializeExternalIdentityClaims())

	var claim ExternalIdentityClaim
	require.NoError(t, DB.Where("provider = ? AND subject = ?", ExternalIdentityProviderTelegram, user.TelegramId).
		First(&claim).Error)
	assert.Equal(t, user.Id, claim.UserId)
}

func TestInitializeExternalIdentityClaimsRejectsAmbiguousLegacyBindings(t *testing.T) {
	truncateTables(t)

	first := User{Username: "telegram-legacy-one", Password: "password", TelegramId: "duplicate-telegram-id", AffCode: "telegram-legacy-one"}
	second := User{Username: "telegram-legacy-two", Password: "password", TelegramId: "duplicate-telegram-id", AffCode: "telegram-legacy-two"}
	require.NoError(t, DB.Create(&first).Error)
	require.NoError(t, DB.Create(&second).Error)

	err := InitializeExternalIdentityClaims()
	assert.ErrorIs(t, err, ErrExternalIdentityAlreadyClaimed)

	var count int64
	require.NoError(t, DB.Model(&ExternalIdentityClaim{}).Count(&count).Error)
	assert.Zero(t, count)
}

func TestCredentialRemovalKeepsTheLastLoginMethod(t *testing.T) {
	truncateTables(t)
	previousPasswordLogin := common.PasswordLoginEnabled
	t.Cleanup(func() { common.PasswordLoginEnabled = previousPasswordLogin })
	common.PasswordLoginEnabled = true

	passkeyUser := User{Username: "passkey-only", AffCode: "passkey-only"}
	require.NoError(t, DB.Create(&passkeyUser).Error)
	require.NoError(t, DB.Create(&PasskeyCredential{
		UserID:       passkeyUser.Id,
		CredentialID: "passkey-only-credential",
		PublicKey:    "passkey-only-key",
	}).Error)
	assert.ErrorIs(t, DeletePasskeyByUserIDWithAuthVersion(passkeyUser.Id, true), ErrLastLoginMethod)
	var passkeys int64
	require.NoError(t, DB.Model(&PasskeyCredential{}).Where("user_id = ?", passkeyUser.Id).Count(&passkeys).Error)
	assert.Equal(t, int64(1), passkeys)

	require.NoError(t, DeletePasskeyByUserIDWithAuthVersion(passkeyUser.Id, false))
	require.NoError(t, DB.Model(&PasskeyCredential{}).Where("user_id = ?", passkeyUser.Id).Count(&passkeys).Error)
	assert.Zero(t, passkeys)

	bindingUser := User{Username: "binding-only", AffCode: "binding-only"}
	require.NoError(t, DB.Create(&bindingUser).Error)
	require.NoError(t, DB.Create(&CustomOAuthProvider{Id: 7, Name: "binding", Slug: "binding", Enabled: true}).Error)
	require.NoError(t, DB.Create(&UserOAuthBinding{
		UserId:         bindingUser.Id,
		ProviderId:     7,
		ProviderUserId: "binding-only-subject",
	}).Error)
	assert.ErrorIs(t, DeleteUserOAuthBinding(bindingUser.Id, 7, true), ErrLastLoginMethod)
	var bindings int64
	require.NoError(t, DB.Model(&UserOAuthBinding{}).Where("user_id = ?", bindingUser.Id).Count(&bindings).Error)
	assert.Equal(t, int64(1), bindings)

	require.NoError(t, DB.Model(&User{}).Where("id = ?", bindingUser.Id).Update("password", "hashed-password").Error)
	require.NoError(t, DeleteUserOAuthBinding(bindingUser.Id, 7, true))
	require.NoError(t, DB.Model(&UserOAuthBinding{}).Where("user_id = ?", bindingUser.Id).Count(&bindings).Error)
	assert.Zero(t, bindings)
}

func TestLoginMethodGuardIgnoresUnusableCredentials(t *testing.T) {
	truncateTables(t)
	previousPasswordLogin := common.PasswordLoginEnabled
	previousGitHub := common.GitHubOAuthEnabled
	previousSMTP := common.SMTPServer
	previousAccount := common.SMTPAccount
	t.Cleanup(func() {
		common.PasswordLoginEnabled = previousPasswordLogin
		common.GitHubOAuthEnabled = previousGitHub
		common.SMTPServer = previousSMTP
		common.SMTPAccount = previousAccount
	})

	cases := []struct {
		name          string
		credential    User
		provider      *CustomOAuthProvider
		passwordLogin bool
		githubEnabled bool
		smtpServer    string
		removable     bool
	}{
		{
			name:       "password while password login is off",
			credential: User{Password: "hashed-password"},
		},
		{
			name:          "password",
			credential:    User{Password: "hashed-password"},
			passwordLogin: true,
			removable:     true,
		},
		{
			name:       "email while password login is off",
			credential: User{Email: "guard-mail-off@example.com"},
			smtpServer: "smtp.example.com",
		},
		{
			name:          "email without a mail server",
			credential:    User{Email: "guard-no-mail@example.com"},
			passwordLogin: true,
		},
		{
			name:          "email",
			credential:    User{Email: "guard-mail@example.com"},
			passwordLogin: true,
			smtpServer:    "smtp.example.com",
			removable:     true,
		},
		{
			name:       "github while the provider is off",
			credential: User{GitHubId: "guard-github-off"},
		},
		{
			name:          "github",
			credential:    User{GitHubId: "guard-github"},
			githubEnabled: true,
			removable:     true,
		},
		{
			name:     "binding to a disabled provider",
			provider: &CustomOAuthProvider{Id: 11, Name: "disabled", Slug: "guard-disabled"},
		},
		{
			name:      "binding",
			provider:  &CustomOAuthProvider{Id: 12, Name: "enabled", Slug: "guard-enabled", Enabled: true},
			removable: true,
		},
	}

	for index, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			common.PasswordLoginEnabled = testCase.passwordLogin
			common.GitHubOAuthEnabled = testCase.githubEnabled
			common.SMTPServer = testCase.smtpServer
			common.SMTPAccount = ""

			user := testCase.credential
			user.Username = fmt.Sprintf("guard-%d", index)
			user.AffCode = fmt.Sprintf("guard-%d", index)
			require.NoError(t, DB.Create(&user).Error)
			require.NoError(t, DB.Create(&PasskeyCredential{
				UserID:       user.Id,
				CredentialID: fmt.Sprintf("guard-credential-%d", index),
				PublicKey:    "guard-key",
			}).Error)
			if testCase.provider != nil {
				require.NoError(t, DB.Create(testCase.provider).Error)
				require.NoError(t, DB.Create(&UserOAuthBinding{
					UserId:         user.Id,
					ProviderId:     testCase.provider.Id,
					ProviderUserId: fmt.Sprintf("guard-subject-%d", index),
				}).Error)
			}

			err := DeletePasskeyByUserIDWithAuthVersion(user.Id, true)
			if testCase.removable {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, ErrLastLoginMethod)
		})
	}
}

func TestDeleteUserOAuthBindingRequiresAnExistingBinding(t *testing.T) {
	truncateTables(t)

	user := User{Username: "binding-missing", Password: "password", AffCode: "binding-missing"}
	require.NoError(t, DB.Create(&user).Error)

	assert.ErrorIs(t, DeleteUserOAuthBinding(user.Id, 21, true), ErrOAuthBindingNotFound)
	assert.ErrorIs(t, DeleteUserOAuthBinding(user.Id, 21, false), ErrOAuthBindingNotFound)
}

func TestDeleteUserKeepsTelegramIdentityReserved(t *testing.T) {
	truncateTables(t)

	user := User{Username: "telegram-deleted", Password: "password", TelegramId: "telegram-deleted-id", AffCode: "telegram-deleted"}
	require.NoError(t, DB.Create(&user).Error)
	require.NoError(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, user.TelegramId, user.Id)
	}))

	require.NoError(t, user.Delete())

	var stored User
	require.NoError(t, DB.Unscoped().First(&stored, user.Id).Error)
	assert.Equal(t, user.TelegramId, stored.TelegramId)

	returning := User{Username: "telegram-returning", Password: "password", AffCode: "telegram-returning"}
	require.NoError(t, DB.Create(&returning).Error)
	assert.ErrorIs(t, DB.Transaction(func(tx *gorm.DB) error {
		return ClaimExternalIdentityWithTx(tx, ExternalIdentityProviderTelegram, user.TelegramId, returning.Id)
	}), ErrExternalIdentityAlreadyClaimed)
}
