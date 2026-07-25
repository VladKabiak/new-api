package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type tokenAPIResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type tokenPageResponse struct {
	Items []tokenResponseItem `json:"items"`
}

type tokenResponseItem struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	KeyPrefix string `json:"key_prefix"`
	Status    int    `json:"status"`
}

type tokenKeyResponse struct {
	Key string `json:"key"`
}

func openTokenControllerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	gin.SetMode(gin.TestMode)
	common.SetDatabaseTypes(common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	common.RedisEnabled = false

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	model.DB = db
	model.LOG_DB = db

	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}
	})

	return db
}

func migrateTokenControllerTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()

	if err := db.AutoMigrate(&model.Token{}); err != nil {
		t.Fatalf("failed to migrate token table: %v", err)
	}
}

func setupTokenControllerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db := openTokenControllerTestDB(t)
	migrateTokenControllerTestDB(t, db)
	return db
}

func seedToken(t *testing.T, db *gorm.DB, userID int, name string, rawKey string) *model.Token {
	t.Helper()

	token := &model.Token{
		UserId:         userID,
		Name:           name,
		KeyHash:        model.HashTokenKey(rawKey),
		KeyPrefix:      model.BuildTokenKeyPrefix(rawKey),
		Status:         common.TokenStatusEnabled,
		CreatedTime:    1,
		AccessedTime:   1,
		ExpiredTime:    -1,
		RemainQuota:    100,
		UnlimitedQuota: true,
		Group:          "default",
	}
	if err := db.Create(token).Error; err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	return token
}

func newAuthenticatedContext(t *testing.T, method string, target string, body any, userID int) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()

	var requestBody *bytes.Reader
	if body != nil {
		payload, err := common.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		requestBody = bytes.NewReader(payload)
	} else {
		requestBody = bytes.NewReader(nil)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, requestBody)
	if body != nil {
		ctx.Request.Header.Set("Content-Type", "application/json")
	}
	ctx.Set("id", userID)
	return ctx, recorder
}

func decodeAPIResponse(t *testing.T, recorder *httptest.ResponseRecorder) tokenAPIResponse {
	t.Helper()

	var response tokenAPIResponse
	if err := common.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode api response: %v", err)
	}
	return response
}

func TestGetAllTokensReturnsOnlyKeyFragment(t *testing.T) {
	db := setupTokenControllerTestDB(t)
	rawKey := "abcd" + strings.Repeat("m", 40) + "wxyz"
	token := seedToken(t, db, 1, "list-token", rawKey)
	seedToken(t, db, 2, "other-user-token", "efgh"+strings.Repeat("n", 40)+"stuv")

	ctx, recorder := newAuthenticatedContext(t, http.MethodGet, "/api/token/?p=1&size=10", nil, 1)
	GetAllTokens(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var page tokenPageResponse
	if err := common.Unmarshal(response.Data, &page); err != nil {
		t.Fatalf("failed to decode token page response: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected exactly one token, got %d", len(page.Items))
	}
	if page.Items[0].KeyPrefix != token.KeyPrefix {
		t.Fatalf("expected key fragment %q, got %q", token.KeyPrefix, page.Items[0].KeyPrefix)
	}
	if strings.Contains(recorder.Body.String(), rawKey) {
		t.Fatalf("list response leaked raw token key: %s", recorder.Body.String())
	}
}

func TestSearchTokensReturnsOnlyKeyFragment(t *testing.T) {
	db := setupTokenControllerTestDB(t)
	rawKey := "ijkl" + strings.Repeat("p", 40) + "mnop"
	token := seedToken(t, db, 1, "searchable-token", rawKey)

	ctx, recorder := newAuthenticatedContext(t, http.MethodGet, "/api/token/search?keyword=searchable-token&p=1&size=10", nil, 1)
	SearchTokens(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var page tokenPageResponse
	if err := common.Unmarshal(response.Data, &page); err != nil {
		t.Fatalf("failed to decode search response: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected exactly one search result, got %d", len(page.Items))
	}
	if page.Items[0].KeyPrefix != token.KeyPrefix {
		t.Fatalf("expected search key fragment %q, got %q", token.KeyPrefix, page.Items[0].KeyPrefix)
	}
	if strings.Contains(recorder.Body.String(), rawKey) {
		t.Fatalf("search response leaked raw token key: %s", recorder.Body.String())
	}
}

func TestGetTokenReturnsOnlyKeyFragment(t *testing.T) {
	db := setupTokenControllerTestDB(t)
	rawKey := "qrst" + strings.Repeat("q", 40) + "uvwx"
	token := seedToken(t, db, 1, "detail-token", rawKey)

	ctx, recorder := newAuthenticatedContext(t, http.MethodGet, "/api/token/"+strconv.Itoa(token.Id), nil, 1)
	ctx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(token.Id)}}
	GetToken(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var detail tokenResponseItem
	if err := common.Unmarshal(response.Data, &detail); err != nil {
		t.Fatalf("failed to decode token detail response: %v", err)
	}
	if detail.KeyPrefix != token.KeyPrefix {
		t.Fatalf("expected detail key fragment %q, got %q", token.KeyPrefix, detail.KeyPrefix)
	}
	if strings.Contains(recorder.Body.String(), rawKey) {
		t.Fatalf("detail response leaked raw token key: %s", recorder.Body.String())
	}
}

func TestUpdateTokenReturnsOnlyKeyFragment(t *testing.T) {
	db := setupTokenControllerTestDB(t)
	rawKey := "yzab" + strings.Repeat("r", 40) + "cdef"
	token := seedToken(t, db, 1, "editable-token", rawKey)

	body := map[string]any{
		"id":                   token.Id,
		"name":                 "updated-token",
		"expired_time":         -1,
		"remain_quota":         100,
		"unlimited_quota":      true,
		"model_limits_enabled": false,
		"model_limits":         "",
		"group":                "default",
		"cross_group_retry":    false,
	}

	ctx, recorder := newAuthenticatedContext(t, http.MethodPut, "/api/token/", body, 1)
	UpdateToken(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var detail tokenResponseItem
	if err := common.Unmarshal(response.Data, &detail); err != nil {
		t.Fatalf("failed to decode token update response: %v", err)
	}
	if detail.KeyPrefix != token.KeyPrefix {
		t.Fatalf("expected update key fragment %q, got %q", token.KeyPrefix, detail.KeyPrefix)
	}
	if strings.Contains(recorder.Body.String(), rawKey) {
		t.Fatalf("update response leaked raw token key: %s", recorder.Body.String())
	}
}

func TestAddTokenReturnsCleartextOnceAndPersistsOnlyHash(t *testing.T) {
	db := setupTokenControllerTestDB(t)

	body := map[string]any{
		"name":                 "created-token",
		"expired_time":         -1,
		"remain_quota":         100,
		"unlimited_quota":      true,
		"model_limits_enabled": false,
		"model_limits":         "",
		"group":                "default",
		"cross_group_retry":    false,
	}
	ctx, recorder := newAuthenticatedContext(t, http.MethodPost, "/api/token/", body, 1)
	AddToken(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected token creation to succeed, got message: %s", response.Message)
	}

	var created tokenKeyResponse
	if err := common.Unmarshal(response.Data, &created); err != nil {
		t.Fatalf("failed to decode created token response: %v", err)
	}
	if created.Key == "" {
		t.Fatal("expected creation response to carry the cleartext key exactly once")
	}

	var stored model.Token
	if err := db.First(&stored, "name = ?", "created-token").Error; err != nil {
		t.Fatalf("failed to load created token: %v", err)
	}
	if stored.KeyHash != model.HashTokenKey(created.Key) {
		t.Fatalf("stored hash %q does not match hash of returned key", stored.KeyHash)
	}
	if stored.KeyPrefix != model.BuildTokenKeyPrefix(created.Key) {
		t.Fatalf("stored prefix %q does not match the returned key", stored.KeyPrefix)
	}

	// Nothing anywhere in the row may reproduce the cleartext.
	var plaintextMatches int64
	if err := db.Table("tokens").
		Where("key_hash = ? OR key_prefix = ?", created.Key, created.Key).
		Count(&plaintextMatches).Error; err != nil {
		t.Fatalf("failed to scan for plaintext key: %v", err)
	}
	if plaintextMatches != 0 {
		t.Fatal("token row stores a value equal to the cleartext key")
	}

	// Reading the token back over the API yields only the fragment.
	detailCtx, detailRecorder := newAuthenticatedContext(t, http.MethodGet, "/api/token/"+strconv.Itoa(stored.Id), nil, 1)
	detailCtx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(stored.Id)}}
	GetToken(detailCtx)

	if strings.Contains(detailRecorder.Body.String(), created.Key) {
		t.Fatalf("token detail re-exposed the cleartext key: %s", detailRecorder.Body.String())
	}
	if !strings.Contains(detailRecorder.Body.String(), stored.KeyPrefix) {
		t.Fatalf("token detail did not return the key fragment: %s", detailRecorder.Body.String())
	}
}
