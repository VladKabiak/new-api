package controller

import (
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const trybitTestSecret = "trybit-test-secret"

func signTrybitToken(t *testing.T, secret string, method jwt.SigningMethod, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	var key any = []byte(secret)
	if method == jwt.SigningMethodNone {
		key = jwt.UnsafeAllowNoneSignatureType
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func trybitTokenClaims(invoiceId string, expiresIn time.Duration) jwt.Claims {
	return &trybitCallbackClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		},
		Id: invoiceId,
	}
}

func TestVerifyTrybitCallbackToken(t *testing.T) {
	cases := []struct {
		name      string
		token     func(t *testing.T) string
		invoiceId string
		wantErr   string
	}{
		{
			name: "accepts a token bound to the callback invoice",
			token: func(t *testing.T) string {
				return signTrybitToken(t, trybitTestSecret, jwt.SigningMethodHS256, trybitTokenClaims("3ZTNHA3W", 5*time.Minute))
			},
			invoiceId: "3ZTNHA3W",
		},
		{
			name: "accepts a prefixed invoice id on either side",
			token: func(t *testing.T) string {
				return signTrybitToken(t, trybitTestSecret, jwt.SigningMethodHS256, trybitTokenClaims("INV-3ZTNHA3W", 5*time.Minute))
			},
			invoiceId: "3ZTNHA3W",
		},
		{
			name: "rejects a token signed with another secret",
			token: func(t *testing.T) string {
				return signTrybitToken(t, "other-secret", jwt.SigningMethodHS256, trybitTokenClaims("3ZTNHA3W", 5*time.Minute))
			},
			invoiceId: "3ZTNHA3W",
			wantErr:   "token rejected",
		},
		{
			name: "rejects an unsigned token",
			token: func(t *testing.T) string {
				return signTrybitToken(t, trybitTestSecret, jwt.SigningMethodNone, trybitTokenClaims("3ZTNHA3W", 5*time.Minute))
			},
			invoiceId: "3ZTNHA3W",
			wantErr:   "token rejected",
		},
		{
			name: "rejects an expired token",
			token: func(t *testing.T) string {
				return signTrybitToken(t, trybitTestSecret, jwt.SigningMethodHS256, trybitTokenClaims("3ZTNHA3W", -2*time.Minute))
			},
			invoiceId: "3ZTNHA3W",
			wantErr:   "token rejected",
		},
		{
			name: "rejects a token without an expiry",
			token: func(t *testing.T) string {
				return signTrybitToken(t, trybitTestSecret, jwt.SigningMethodHS256, &trybitCallbackClaims{Id: "3ZTNHA3W"})
			},
			invoiceId: "3ZTNHA3W",
			wantErr:   "token rejected",
		},
		{
			name: "rejects a token that outlives the replay window",
			token: func(t *testing.T) string {
				return signTrybitToken(t, trybitTestSecret, jwt.SigningMethodHS256, trybitTokenClaims("3ZTNHA3W", 24*time.Hour))
			},
			invoiceId: "3ZTNHA3W",
			wantErr:   "token expiry out of range",
		},
		{
			name: "rejects a token that binds no invoice",
			token: func(t *testing.T) string {
				return signTrybitToken(t, trybitTestSecret, jwt.SigningMethodHS256, trybitTokenClaims("", 5*time.Minute))
			},
			invoiceId: "3ZTNHA3W",
			wantErr:   "token carries no invoice id",
		},
		{
			name: "rejects a token issued for another invoice",
			token: func(t *testing.T) string {
				return signTrybitToken(t, trybitTestSecret, jwt.SigningMethodHS256, trybitTokenClaims("OTHER123", 5*time.Minute))
			},
			invoiceId: "3ZTNHA3W",
			wantErr:   "does not match callback invoice id",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			req := &trybitNotifyRequest{
				Status:    trybitStatusSuccess,
				InvoiceId: testCase.invoiceId,
				OrderId:   "TRYBIT-1-1787930619786-qho0pq",
				Token:     testCase.token(t),
			}

			err := verifyTrybitCallbackToken(trybitTestSecret, req)

			if testCase.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), testCase.wantErr)
		})
	}
}

func TestNormalizeTrybitInvoiceId(t *testing.T) {
	assert.Equal(t, "3ZTNHA3W", normalizeTrybitInvoiceId("INV-3ZTNHA3W"))
	assert.Equal(t, "3ZTNHA3W", normalizeTrybitInvoiceId("3ZTNHA3W"))
	assert.Equal(t, "", normalizeTrybitInvoiceId(""))
}

func TestTrybitPayMoneyMatchesCreditedUnits(t *testing.T) {
	general := operation_setting.GetGeneralSetting()
	payment := operation_setting.GetPaymentSetting()
	originalDisplay := general.QuotaDisplayType
	originalQuotaPerUnit := common.QuotaPerUnit
	originalUnitPrice := setting.TrybitUnitPrice
	originalDiscount := payment.AmountDiscount
	t.Cleanup(func() {
		general.QuotaDisplayType = originalDisplay
		common.QuotaPerUnit = originalQuotaPerUnit
		setting.TrybitUnitPrice = originalUnitPrice
		payment.AmountDiscount = originalDiscount
	})

	common.QuotaPerUnit = 500000
	setting.TrybitUnitPrice = 2
	payment.AmountDiscount = map[int]float64{}

	cases := []struct {
		name        string
		displayType string
		amount      int64
		wantUnits   int64
		wantMoney   float64
	}{
		{
			name:        "tokens amount on a unit boundary",
			displayType: operation_setting.QuotaDisplayTypeTokens,
			amount:      2500000,
			wantUnits:   5,
			wantMoney:   10,
		},
		{
			name:        "tokens amount with a fractional unit is charged as the credited units",
			displayType: operation_setting.QuotaDisplayTypeTokens,
			amount:      2600000,
			wantUnits:   5,
			wantMoney:   10,
		},
		{
			name:        "tokens amount below one unit is priced at zero so the handler rejects it",
			displayType: operation_setting.QuotaDisplayTypeTokens,
			amount:      100000,
			wantUnits:   1,
			wantMoney:   0,
		},
		{
			name:        "currency amount is charged per credited unit",
			displayType: operation_setting.QuotaDisplayTypeUSD,
			amount:      5,
			wantUnits:   5,
			wantMoney:   10,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			general.QuotaDisplayType = testCase.displayType

			assert.Equal(t, testCase.wantUnits, normalizeTrybitTopUpAmount(testCase.amount))
			assert.Equal(t, testCase.wantMoney, getTrybitPayMoney(testCase.amount, "default"))
		})
	}
}
