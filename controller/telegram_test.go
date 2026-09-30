package controller

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestVerifyTelegramAuthorization(t *testing.T) {
	const token = "telegram-test-token"
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name     string
		authDate time.Time
		mutate   func(url.Values)
		wantID   string
		wantErr  string
	}{
		{name: "valid", authDate: now, wantID: "123456"},
		{name: "small future clock skew", authDate: now.Add(90 * time.Second), wantID: "123456"},
		{name: "expired", authDate: now.Add(-telegramAuthorizationMaxAge - time.Second), wantErr: "expired"},
		{name: "too far in future", authDate: now.Add(telegramAuthorizationFutureSkew + time.Second), wantErr: "expired"},
		{name: "invalid signature", authDate: now, mutate: func(values url.Values) { values.Set("hash", "00") }, wantErr: "signature"},
		{name: "unsigned flow token query is rejected", authDate: now, mutate: func(values url.Values) { values.Set("flow_token", "must-be-in-path") }, wantErr: "signature"},
		{name: "duplicate parameter", authDate: now, mutate: func(values url.Values) { values["id"] = append(values["id"], "654321") }, wantErr: "duplicate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := signedTelegramAuthorization(token, tt.authDate)
			if tt.mutate != nil {
				tt.mutate(params)
			}

			telegramID, err := verifyTelegramAuthorization(params, token, now)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Empty(t, telegramID)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantID, telegramID)
		})
	}
}

func signedTelegramAuthorization(token string, authDate time.Time) url.Values {
	params := url.Values{
		"auth_date":  {strconv.FormatInt(authDate.Unix(), 10)},
		"first_name": {"Test"},
		"id":         {"123456"},
	}
	signTelegramAuthorization(token, params)
	return params
}

func signTelegramAuthorization(token string, params url.Values) {
	keys := make([]string, 0, len(params))
	for key := range params {
		if key == "hash" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	dataCheck := make([]string, 0, len(keys))
	for _, key := range keys {
		dataCheck = append(dataCheck, key+"="+params.Get(key))
	}
	secret := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write([]byte(strings.Join(dataCheck, "\n")))
	params.Set("hash", hex.EncodeToString(mac.Sum(nil)))
}

func createTelegramBindTestFlow(t *testing.T, db *gorm.DB, name string, status int, now time.Time) (*model.User, string) {
	t.Helper()
	user := &model.User{
		Username: name, Password: "password-placeholder", Role: common.RoleCommonUser,
		Status: status, Group: "default", AuthVersion: 1, AffCode: name,
	}
	require.NoError(t, db.Create(user).Error)
	session := &model.UserSession{
		SID: name + "-session", UserID: user.Id, Version: 1, UserAuthVersion: user.AuthVersion,
		Status: model.UserSessionStatusActive, RefreshHash: name + "-refresh-hash", LoginMethod: "password",
		CreatedAt: now.Unix(), LastActiveAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	require.NoError(t, model.CreateUserSession(session))
	flowToken, _, err := model.CreateAuthFlow(model.AuthFlowCreate{
		Purpose: model.AuthFlowPurposeTelegramBind, UserId: user.Id, SessionId: session.SID,
		ExpiresAt: now.Add(time.Minute),
	})
	require.NoError(t, err)
	return user, flowToken
}

func assertTelegramBindRedirect(t *testing.T, response *httptest.ResponseRecorder, flowToken, errorCode string) {
	t.Helper()
	require.Equal(t, http.StatusFound, response.Code)
	location, err := url.Parse(response.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/oauth/telegram", location.Path)
	assert.Equal(t, "error", location.Query().Get("telegram_bind"))
	assert.Equal(t, flowToken, location.Query().Get("flow_token"))
	assert.Equal(t, errorCode, location.Query().Get("error_code"))
	assert.Empty(t, location.Query().Get("error_description"))
	assert.Empty(t, location.Query().Get("message"))
}

func TestTelegramBindFailureResponseContract(t *testing.T) {
	failures := []struct {
		name      string
		errorCode string
	}{
		{name: "disabled", errorCode: telegramBindErrorDisabled},
		{name: "invalid request", errorCode: telegramBindErrorInvalidRequest},
		{name: "invalid flow", errorCode: telegramBindErrorFlowInvalid},
		{name: "invalid session", errorCode: telegramBindErrorSessionInvalid},
		{name: "already bound", errorCode: telegramBindErrorAlreadyBound},
		{name: "deleted user", errorCode: telegramBindErrorUserDeleted},
		{name: "disabled user", errorCode: telegramBindErrorUserDisabled},
		{name: "internal error", errorCode: telegramBindErrorInternal},
	}

	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(response)
			context.Params = gin.Params{{Key: "flow_token", Value: "flow token"}}
			context.Request = httptest.NewRequest(http.MethodGet, "/api/oauth/telegram/bind/flow-token", nil)

			telegramBindFailure(context, failure.errorCode)

			assertTelegramBindRedirect(t, response, "flow token", failure.errorCode)
		})
	}
}

func TestTelegramBindCommitsFlowAssertionAndBindingAtomically(t *testing.T) {
	previousDB := model.DB
	previousType := common.MainDatabaseType()
	previousRedis := common.RedisEnabled
	previousEnabled := common.TelegramOAuthEnabled
	previousToken := common.TelegramBotToken
	previousSecret := common.SessionSecret
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.User{},
		&model.UserSession{},
		&model.AuthFlow{},
		&model.ExternalIdentityClaim{},
	))
	model.DB = db
	common.SetMainDatabaseType(common.DatabaseTypeSQLite)
	common.RedisEnabled = false
	common.TelegramOAuthEnabled = true
	common.TelegramBotToken = "telegram-bind-test-token"
	common.SessionSecret = "telegram-bind-session-secret"
	t.Cleanup(func() {
		model.DB = previousDB
		common.SetMainDatabaseType(previousType)
		common.RedisEnabled = previousRedis
		common.TelegramOAuthEnabled = previousEnabled
		common.TelegramBotToken = previousToken
		common.SessionSecret = previousSecret
	})

	user := &model.User{
		Username: "telegram-bind-user", Password: "password-placeholder", Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: "telegram-bind-user",
	}
	require.NoError(t, db.Create(user).Error)
	now := time.Now()
	session := &model.UserSession{
		SID: "telegram-bind-session", UserID: user.Id, Version: 1, UserAuthVersion: user.AuthVersion,
		Status: model.UserSessionStatusActive, RefreshHash: "refresh-hash", LoginMethod: "password",
		CreatedAt: now.Unix(), LastActiveAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	require.NoError(t, model.CreateUserSession(session))
	flowToken, _, err := model.CreateAuthFlow(model.AuthFlowCreate{
		Purpose: model.AuthFlowPurposeTelegramBind, UserId: user.Id, SessionId: session.SID,
		ExpiresAt: now.Add(time.Minute),
	})
	require.NoError(t, err)
	params := signedTelegramAuthorization(common.TelegramBotToken, now)
	router := gin.New()
	router.GET("/api/oauth/telegram/bind/:flow_token", TelegramBind)

	common.TelegramOAuthEnabled = false
	request := httptest.NewRequest(http.MethodGet, "/api/oauth/telegram/bind/disabled-flow", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertTelegramBindRedirect(t, response, "disabled-flow", telegramBindErrorDisabled)
	common.TelegramOAuthEnabled = true

	request = httptest.NewRequest(http.MethodGet, "/api/oauth/telegram/bind/invalid-request", nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertTelegramBindRedirect(t, response, "invalid-request", telegramBindErrorInvalidRequest)

	request = httptest.NewRequest(http.MethodGet, "/api/oauth/telegram/bind/missing-flow?"+params.Encode(), nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertTelegramBindRedirect(t, response, "missing-flow", telegramBindErrorFlowInvalid)

	invalidSessionFlowToken, _, err := model.CreateAuthFlow(model.AuthFlowCreate{
		Purpose: model.AuthFlowPurposeTelegramBind, UserId: user.Id, SessionId: "missing-session",
		ExpiresAt: now.Add(time.Minute),
	})
	require.NoError(t, err)
	request = httptest.NewRequest(
		http.MethodGet,
		"/api/oauth/telegram/bind/"+invalidSessionFlowToken+"?"+params.Encode(),
		nil,
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertTelegramBindRedirect(t, response, invalidSessionFlowToken, telegramBindErrorSessionInvalid)
	invalidSessionFlow, err := model.GetAuthFlow(invalidSessionFlowToken, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeTelegramBind})
	require.NoError(t, err)
	assert.Nil(t, invalidSessionFlow.ConsumedAt)

	request = httptest.NewRequest(http.MethodGet, "/api/oauth/telegram/bind/"+flowToken+"?"+params.Encode(), nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusFound, response.Code)
	assert.Equal(t, "/oauth/telegram?telegram_bind=success&flow_token="+url.QueryEscape(flowToken), response.Header().Get("Location"))
	var storedUser model.User
	require.NoError(t, db.First(&storedUser, user.Id).Error)
	assert.Equal(t, "123456", storedUser.TelegramId)
	var identityClaim model.ExternalIdentityClaim
	require.NoError(t, db.Where("provider = ? AND subject = ?", model.ExternalIdentityProviderTelegram, "123456").
		First(&identityClaim).Error)
	assert.Equal(t, user.Id, identityClaim.UserId)
	_, err = model.GetAuthFlow(flowToken, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeTelegramBind})
	assert.ErrorIs(t, err, model.ErrAuthFlowConsumed)

	replayFlowToken, _, err := model.CreateAuthFlow(model.AuthFlowCreate{
		Purpose: model.AuthFlowPurposeTelegramBind, UserId: user.Id, SessionId: session.SID,
		ExpiresAt: now.Add(time.Minute),
	})
	require.NoError(t, err)
	request = httptest.NewRequest(http.MethodGet, "/api/oauth/telegram/bind/"+replayFlowToken+"?"+params.Encode(), nil)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertTelegramBindRedirect(t, response, replayFlowToken, telegramBindErrorInvalidRequest)
	replayFlow, err := model.GetAuthFlow(replayFlowToken, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeTelegramBind})
	require.NoError(t, err)
	assert.Nil(t, replayFlow.ConsumedAt)

	competingUser := &model.User{
		Username: "telegram-bind-competing-user", Password: "password-placeholder", Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: "telegram-bind-competing-user",
	}
	require.NoError(t, db.Create(competingUser).Error)
	competingSession := &model.UserSession{
		SID: "telegram-bind-competing-session", UserID: competingUser.Id, Version: 1,
		UserAuthVersion: competingUser.AuthVersion, Status: model.UserSessionStatusActive,
		RefreshHash: "competing-refresh-hash", LoginMethod: "password",
		CreatedAt: now.Unix(), LastActiveAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	}
	require.NoError(t, model.CreateUserSession(competingSession))
	competingFlowToken, _, err := model.CreateAuthFlow(model.AuthFlowCreate{
		Purpose: model.AuthFlowPurposeTelegramBind, UserId: competingUser.Id, SessionId: competingSession.SID,
		ExpiresAt: now.Add(time.Minute),
	})
	require.NoError(t, err)
	competingParams := signedTelegramAuthorization(common.TelegramBotToken, now)
	competingParams.Set("first_name", "Competing")
	signTelegramAuthorization(common.TelegramBotToken, competingParams)
	request = httptest.NewRequest(
		http.MethodGet,
		"/api/oauth/telegram/bind/"+competingFlowToken+"?"+competingParams.Encode(),
		nil,
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertTelegramBindRedirect(t, response, competingFlowToken, telegramBindErrorAlreadyBound)

	require.NoError(t, db.First(competingUser, competingUser.Id).Error)
	assert.Empty(t, competingUser.TelegramId)
	competingFlow, err := model.GetAuthFlow(competingFlowToken, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeTelegramBind})
	require.NoError(t, err)
	assert.Nil(t, competingFlow.ConsumedAt)
	competingAssertion, competingAssertionExpiry, err := telegramAuthorizationClaim(competingParams, time.Now())
	require.NoError(t, err)
	require.NoError(t, model.ClaimExternalAuthAssertion(
		model.AuthFlowPurposeTelegramAssertion,
		competingAssertion,
		competingAssertionExpiry,
	))

	disabledUser, disabledFlowToken := createTelegramBindTestFlow(
		t, db, "telegram-bind-disabled-user", common.UserStatusDisabled, now,
	)
	disabledParams := signedTelegramAuthorization(common.TelegramBotToken, now)
	disabledParams.Set("id", "700001")
	disabledParams.Set("first_name", "Disabled")
	signTelegramAuthorization(common.TelegramBotToken, disabledParams)
	request = httptest.NewRequest(
		http.MethodGet,
		"/api/oauth/telegram/bind/"+disabledFlowToken+"?"+disabledParams.Encode(),
		nil,
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertTelegramBindRedirect(t, response, disabledFlowToken, telegramBindErrorUserDisabled)
	var storedDisabledUser model.User
	require.NoError(t, db.First(&storedDisabledUser, disabledUser.Id).Error)
	assert.Empty(t, storedDisabledUser.TelegramId)
	disabledFlow, err := model.GetAuthFlow(disabledFlowToken, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeTelegramBind})
	require.NoError(t, err)
	assert.Nil(t, disabledFlow.ConsumedAt)
	disabledAssertion, disabledAssertionExpiry, err := telegramAuthorizationClaim(disabledParams, time.Now())
	require.NoError(t, err)
	require.NoError(t, model.ClaimExternalAuthAssertion(
		model.AuthFlowPurposeTelegramAssertion,
		disabledAssertion,
		disabledAssertionExpiry,
	))

	deletedUser, deletedFlowToken := createTelegramBindTestFlow(
		t, db, "telegram-bind-deleted-user", common.UserStatusEnabled, now,
	)
	require.NoError(t, db.Delete(deletedUser).Error)
	deletedParams := signedTelegramAuthorization(common.TelegramBotToken, now)
	deletedParams.Set("id", "700002")
	deletedParams.Set("first_name", "Deleted")
	signTelegramAuthorization(common.TelegramBotToken, deletedParams)
	request = httptest.NewRequest(
		http.MethodGet,
		"/api/oauth/telegram/bind/"+deletedFlowToken+"?"+deletedParams.Encode(),
		nil,
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertTelegramBindRedirect(t, response, deletedFlowToken, telegramBindErrorUserDeleted)
	deletedFlow, err := model.GetAuthFlow(deletedFlowToken, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeTelegramBind})
	require.NoError(t, err)
	assert.Nil(t, deletedFlow.ConsumedAt)
	deletedAssertion, deletedAssertionExpiry, err := telegramAuthorizationClaim(deletedParams, time.Now())
	require.NoError(t, err)
	require.NoError(t, model.ClaimExternalAuthAssertion(
		model.AuthFlowPurposeTelegramAssertion,
		deletedAssertion,
		deletedAssertionExpiry,
	))

	_, internalFlowToken := createTelegramBindTestFlow(
		t, db, "telegram-bind-internal-error", common.UserStatusEnabled, now,
	)
	internalParams := signedTelegramAuthorization(common.TelegramBotToken, now)
	internalParams.Set("id", "700003")
	internalParams.Set("first_name", "Internal")
	signTelegramAuthorization(common.TelegramBotToken, internalParams)
	forcedError := errors.New("forced telegram session query failure")
	const callbackName = "test:telegram-bind-session-query-failure"
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table != "user_sessions" {
			return
		}
		if _, inTransaction := tx.Statement.ConnPool.(gorm.TxCommitter); inTransaction {
			tx.AddError(forcedError)
		}
	}))
	request = httptest.NewRequest(
		http.MethodGet,
		"/api/oauth/telegram/bind/"+internalFlowToken+"?"+internalParams.Encode(),
		nil,
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	db.Callback().Query().Remove(callbackName)
	assertTelegramBindRedirect(t, response, internalFlowToken, telegramBindErrorInternal)
	assert.NotContains(t, response.Header().Get("Location"), forcedError.Error())
	internalFlow, err := model.GetAuthFlow(internalFlowToken, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeTelegramBind})
	require.NoError(t, err)
	assert.Nil(t, internalFlow.ConsumedAt)
	internalAssertion, internalAssertionExpiry, err := telegramAuthorizationClaim(internalParams, time.Now())
	require.NoError(t, err)
	require.NoError(t, model.ClaimExternalAuthAssertion(
		model.AuthFlowPurposeTelegramAssertion,
		internalAssertion,
		internalAssertionExpiry,
	))

}

type telegramLoginResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func telegramLogin(t *testing.T, router *gin.Engine, params url.Values) (*httptest.ResponseRecorder, telegramLoginResult) {
	t.Helper()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/oauth/telegram/login?"+params.Encode(), nil))
	var body telegramLoginResult
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &body))
	return response, body
}

func setupTelegramLoginTest(t *testing.T) (*gin.Engine, *gorm.DB) {
	t.Helper()
	previousDB := model.DB
	previousLogDB := model.LOG_DB
	previousType := common.MainDatabaseType()
	previousRedis := common.RedisEnabled
	previousEnabled := common.TelegramOAuthEnabled
	previousToken := common.TelegramBotToken
	previousSecret := common.SessionSecret
	previousRegister := common.RegisterEnabled
	previousQuota := common.QuotaForNewUser
	previousInvitee := common.QuotaForInvitee
	previousActiveLimit := common.UserSessionActiveLimit
	previousIssuanceLimit := common.UserSessionIssuanceLimit
	previousPayment := *operation_setting.GetPaymentSetting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.User{},
		&model.UserSession{},
		&model.AuthFlow{},
		&model.ExternalIdentityClaim{},
		&model.PasskeyCredential{},
		&model.UserOAuthBinding{},
		&model.Log{},
	))
	model.DB = db
	model.LOG_DB = db
	common.SetMainDatabaseType(common.DatabaseTypeSQLite)
	common.RedisEnabled = false
	common.TelegramOAuthEnabled = true
	common.TelegramBotToken = "telegram-login-test-token"
	common.SessionSecret = "telegram-login-session-secret"
	common.RegisterEnabled = true
	common.QuotaForNewUser = 0
	common.QuotaForInvitee = 0
	common.UserSessionActiveLimit = common.DefaultUserSessionActiveLimit
	common.UserSessionIssuanceLimit = common.DefaultUserSessionIssuanceLimit
	t.Cleanup(func() {
		model.DB = previousDB
		model.LOG_DB = previousLogDB
		common.SetMainDatabaseType(previousType)
		common.RedisEnabled = previousRedis
		common.TelegramOAuthEnabled = previousEnabled
		common.TelegramBotToken = previousToken
		common.SessionSecret = previousSecret
		common.RegisterEnabled = previousRegister
		common.QuotaForNewUser = previousQuota
		common.QuotaForInvitee = previousInvitee
		common.UserSessionActiveLimit = previousActiveLimit
		common.UserSessionIssuanceLimit = previousIssuanceLimit
		*operation_setting.GetPaymentSetting() = previousPayment
	})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/oauth/telegram/login", TelegramLogin)
	return router, db
}

func TestTelegramLoginRegistersFirstTimeAccount(t *testing.T) {
	router, db := setupTelegramLoginTest(t)

	params := signedTelegramAuthorization(common.TelegramBotToken, time.Now())
	params.Set("username", "Екатерина")
	params.Set("first_name", "Екатерина")
	params.Set("last_name", "Владимировна")
	signTelegramAuthorization(common.TelegramBotToken, params)

	response, body := telegramLogin(t, router, params)
	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, body.Success)

	var users []model.User
	require.NoError(t, db.Find(&users).Error)
	require.Len(t, users, 1)
	assert.Equal(t, "123456", users[0].TelegramId)
	assert.Equal(t, "tg123456", users[0].Username)
	assert.Equal(t, "Екатерина Владимиров", users[0].DisplayName)
	assert.Equal(t, common.RoleCommonUser, users[0].Role)
	assert.Equal(t, common.UserStatusEnabled, users[0].Status)

	var claims []model.ExternalIdentityClaim
	require.NoError(t, db.Find(&claims).Error)
	require.Len(t, claims, 1)
	assert.Equal(t, users[0].Id, claims[0].UserId)
	assert.Equal(t, model.ExternalIdentityProviderTelegram, claims[0].Provider)
	assert.Equal(t, "123456", claims[0].Subject)
}

func TestTelegramLoginFallsBackToTelegramIdUsername(t *testing.T) {
	router, db := setupTelegramLoginTest(t)

	params := signedTelegramAuthorization(common.TelegramBotToken, time.Now())
	params.Set("id", "1234567890123456")
	params.Set("username", "")
	params.Set("first_name", "")
	signTelegramAuthorization(common.TelegramBotToken, params)

	response, body := telegramLogin(t, router, params)
	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, body.Success)

	var user model.User
	require.NoError(t, db.First(&user).Error)
	assert.Equal(t, "tg1234567890", user.Username)
	assert.Equal(t, "tg1234567890", user.DisplayName)
}

func TestTelegramLoginRejectsReplayedAssertion(t *testing.T) {
	router, db := setupTelegramLoginTest(t)

	params := signedTelegramAuthorization(common.TelegramBotToken, time.Now())
	_, body := telegramLogin(t, router, params)
	require.True(t, body.Success)

	response, body := telegramLogin(t, router, params)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.False(t, body.Success)
	assert.Equal(t, i18n.MsgUserTelegramAssertionSpent, body.Message)

	var users []model.User
	require.NoError(t, db.Find(&users).Error)
	assert.Len(t, users, 1)
}

func TestTelegramLoginSignsInReturningAccount(t *testing.T) {
	router, db := setupTelegramLoginTest(t)
	now := time.Now()

	_, body := telegramLogin(t, router, signedTelegramAuthorization(common.TelegramBotToken, now))
	require.True(t, body.Success)
	var registered model.User
	require.NoError(t, db.First(&registered).Error)

	response, body := telegramLogin(t, router, signedTelegramAuthorization(common.TelegramBotToken, now.Add(time.Second)))
	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, body.Success)

	var users []model.User
	require.NoError(t, db.Find(&users).Error)
	require.Len(t, users, 1)
	assert.Equal(t, registered.Id, users[0].Id)
}

func TestTelegramLoginKeepsAssertionWhenRegistrationIsDisabled(t *testing.T) {
	router, db := setupTelegramLoginTest(t)
	common.RegisterEnabled = false

	params := signedTelegramAuthorization(common.TelegramBotToken, time.Now())
	response, body := telegramLogin(t, router, params)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.False(t, body.Success)
	var users []model.User
	require.NoError(t, db.Find(&users).Error)
	assert.Empty(t, users)

	common.RegisterEnabled = true
	response, body = telegramLogin(t, router, params)
	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, body.Success)
	require.NoError(t, db.Find(&users).Error)
	require.Len(t, users, 1)
}

func TestTelegramLoginRefusesIdentityOfDeletedAccount(t *testing.T) {
	router, db := setupTelegramLoginTest(t)
	now := time.Now()

	_, body := telegramLogin(t, router, signedTelegramAuthorization(common.TelegramBotToken, now))
	require.True(t, body.Success)
	var registered model.User
	require.NoError(t, db.First(&registered).Error)
	require.NoError(t, registered.Delete())

	var claims int64
	require.NoError(t, db.Model(&model.ExternalIdentityClaim{}).Count(&claims).Error)
	require.EqualValues(t, 1, claims)
	var flowsBefore int64
	require.NoError(t, db.Model(&model.AuthFlow{}).Count(&flowsBefore).Error)

	response, body := telegramLogin(t, router, signedTelegramAuthorization(common.TelegramBotToken, now.Add(time.Second)))
	require.Equal(t, http.StatusOK, response.Code)
	assert.False(t, body.Success)
	assert.Equal(t, i18n.MsgOAuthUserDeleted, body.Message)

	var users []model.User
	require.NoError(t, db.Unscoped().Find(&users).Error)
	require.Len(t, users, 1)
	assert.Equal(t, registered.Id, users[0].Id)
	var flowsAfter int64
	require.NoError(t, db.Model(&model.AuthFlow{}).Count(&flowsAfter).Error)
	assert.Equal(t, flowsBefore, flowsAfter)
}

func TestTelegramLoginKeepsAssertionWhenAccountIsDisabled(t *testing.T) {
	router, db := setupTelegramLoginTest(t)

	user := model.User{
		Username:   "telegram-disabled",
		TelegramId: "123456",
		AffCode:    "telegram-disabled",
		Status:     common.UserStatusDisabled,
	}
	require.NoError(t, db.Create(&user).Error)

	params := signedTelegramAuthorization(common.TelegramBotToken, time.Now())
	response, body := telegramLogin(t, router, params)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.False(t, body.Success)
	var flows int64
	require.NoError(t, db.Model(&model.AuthFlow{}).Count(&flows).Error)
	assert.Zero(t, flows)

	require.NoError(t, db.Model(&model.User{}).Where("id = ?", user.Id).
		Update("status", common.UserStatusEnabled).Error)
	response, body = telegramLogin(t, router, params)
	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, body.Success)
}

func TestTelegramLoginCreditsTheInviter(t *testing.T) {
	router, db := setupTelegramLoginTest(t)
	common.QuotaForInvitee = 500
	payment := operation_setting.GetPaymentSetting()
	payment.ComplianceConfirmed = true
	payment.ComplianceTermsVersion = operation_setting.CurrentComplianceTermsVersion

	inviter := model.User{Username: "inviter", Password: "password", AffCode: "invite-code"}
	require.NoError(t, db.Create(&inviter).Error)

	params := signedTelegramAuthorization(common.TelegramBotToken, time.Now())
	params.Set("aff", "invite-code")

	response, body := telegramLogin(t, router, params)
	require.Equal(t, http.StatusOK, response.Code)
	require.True(t, body.Success)

	var invitee model.User
	require.NoError(t, db.Where("telegram_id = ?", "123456").First(&invitee).Error)
	assert.Equal(t, 500, invitee.Quota)
}
