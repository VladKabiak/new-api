package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shopspring/decimal"
	"github.com/thanhpk/randstr"
)

const (
	trybitInvoiceCreateURL      = "https://api.trybit.com/v2/invoice/create"
	trybitInvoiceInfoURL        = "https://api.trybit.com/v2/invoice/merchant/info"
	trybitInvoiceCurrency       = "USD"
	trybitStatusSuccess         = "success"
	trybitInvoiceStatusPaid     = "paid"
	trybitInvoiceStatusOverpaid = "overpaid"
	trybitInvoiceStatusCanceled = "canceled"
	trybitInvoiceIdPrefix       = "INV-"
	trybitExpiryLayout          = "2006-01-02 15:04:05.999999"
	trybitRequestTimeout        = 30 * time.Second
	trybitResponseLimit         = 1 << 20
	trybitCallbackTokenTTL      = 5 * time.Minute
	trybitCallbackLeeway        = 30 * time.Second
)

type TrybitPayRequest struct {
	Amount int64 `json:"amount"`
}

type trybitInvoice struct {
	InvoiceId string
	PayLink   string
	ExpiresAt int64
}

type trybitInvoiceCreateRequest struct {
	ShopId   string  `json:"shop_id"`
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
	OrderId  string  `json:"order_id"`
	Email    string  `json:"email,omitempty"`
}

type trybitInvoiceCreateResponse struct {
	Status string `json:"status"`
	Result struct {
		Uuid       string `json:"uuid"`
		Link       string `json:"link"`
		ExpiryDate string `json:"expiry_date"`
	} `json:"result"`
}

// The callback token only ever carries the invoice id, so that is the single
// identifier it can bind; the order is bound to the invoice by our own stored
// provider ref rather than by anything the callback claims.
type trybitCallbackClaims struct {
	jwt.RegisteredClaims
	Id string `json:"id"`
}

type trybitInvoiceInfoRequest struct {
	Uuids []string `json:"uuids"`
}

type trybitInvoiceInfoResponse struct {
	Status string `json:"status"`
	Result []struct {
		Uuid    string `json:"uuid"`
		Status  string `json:"status"`
		OrderId string `json:"order_id"`
	} `json:"result"`
}

type trybitNotifyRequest struct {
	Status       string  `json:"status" form:"status"`
	InvoiceId    string  `json:"invoice_id" form:"invoice_id"`
	OrderId      string  `json:"order_id" form:"order_id"`
	Token        string  `json:"token" form:"token"`
	Currency     string  `json:"currency" form:"currency"`
	AmountCrypto float64 `json:"amount_crypto" form:"amount_crypto"`
}

func RequestTrybitAmount(c *gin.Context) {
	var req TrybitPayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "参数错误"})
		return
	}

	if req.Amount < int64(setting.TrybitMinTopUp) {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": fmt.Sprintf("充值数量不能小于 %d", setting.TrybitMinTopUp)})
		return
	}

	id := c.GetInt("id")
	if rejectInvalidTopUpQuota(c, id, req.Amount) {
		return
	}

	group, err := model.GetUserGroup(id, true)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "获取用户分组失败"})
		return
	}

	payMoney := getTrybitPayMoney(req.Amount, group)
	if payMoney <= 0.01 {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "充值金额过低"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "success", "data": decimal.NewFromFloat(payMoney).StringFixed(2)})
}

func RequestTrybitPay(c *gin.Context) {
	var req TrybitPayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "参数错误"})
		return
	}

	ctx := c.Request.Context()

	if !isTrybitTopUpEnabled() {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "Trybit 支付未启用"})
		return
	}

	if req.Amount < int64(setting.TrybitMinTopUp) {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": fmt.Sprintf("充值数量不能小于 %d", setting.TrybitMinTopUp)})
		return
	}

	id := c.GetInt("id")
	if rejectInvalidTopUpQuota(c, id, req.Amount) {
		return
	}

	user, err := model.GetUserById(id, false)
	if err != nil || user == nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "用户不存在"})
		return
	}

	group, err := model.GetUserGroup(id, true)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "获取用户分组失败"})
		return
	}

	payMoney := getTrybitPayMoney(req.Amount, group)
	if payMoney <= 0.01 {
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "充值金额过低"})
		return
	}

	tradeNo := fmt.Sprintf("TRYBIT-%d-%d-%s", id, time.Now().UnixMilli(), randstr.String(6))

	topUp := &model.TopUp{
		UserId:          id,
		Amount:          normalizeTrybitTopUpAmount(req.Amount),
		Money:           payMoney,
		TradeNo:         tradeNo,
		PaymentMethod:   model.PaymentMethodTrybit,
		PaymentProvider: model.PaymentProviderTrybit,
		CreateTime:      time.Now().Unix(),
		Status:          common.TopUpStatusPending,
	}
	if err := topUp.Insert(); err != nil {
		logger.LogError(ctx, fmt.Sprintf("Trybit 创建充值订单失败 user_id=%d trade_no=%s amount=%d error=%q", id, tradeNo, req.Amount, err.Error()))
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "创建订单失败"})
		return
	}

	invoice, err := genTrybitInvoice(ctx, tradeNo, payMoney, user.Email)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("Trybit 创建发票失败 user_id=%d trade_no=%s money=%.2f error=%q", id, tradeNo, payMoney, err.Error()))
		markTrybitTopUpFailed(ctx, tradeNo)
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "拉起支付失败"})
		return
	}

	if err := model.BindTopUpProviderRef(tradeNo, invoice.InvoiceId, invoice.ExpiresAt); err != nil {
		logger.LogError(ctx, fmt.Sprintf("Trybit 绑定发票信息失败 trade_no=%s invoice_id=%s error=%q", tradeNo, invoice.InvoiceId, err.Error()))
		markTrybitTopUpFailed(ctx, tradeNo)
		c.JSON(http.StatusOK, gin.H{"message": "error", "data": "拉起支付失败"})
		return
	}

	logger.LogInfo(ctx, fmt.Sprintf("Trybit 充值订单创建成功 user_id=%d trade_no=%s invoice_id=%s amount=%d money=%.2f expires_at=%d", id, tradeNo, invoice.InvoiceId, topUp.Amount, payMoney, invoice.ExpiresAt))

	c.JSON(http.StatusOK, gin.H{
		"message": "success",
		"data": gin.H{
			"pay_link":   invoice.PayLink,
			"order_id":   tradeNo,
			"expires_at": invoice.ExpiresAt,
		},
	})
}

func markTrybitTopUpFailed(ctx context.Context, tradeNo string) {
	if err := model.UpdatePendingTopUpStatus(tradeNo, model.PaymentProviderTrybit, common.TopUpStatusFailed); err != nil &&
		!errors.Is(err, model.ErrTopUpNotFound) &&
		!errors.Is(err, model.ErrTopUpStatusInvalid) {
		logger.LogError(ctx, fmt.Sprintf("Trybit 标记充值订单失败状态失败 trade_no=%s error=%q", tradeNo, err.Error()))
	}
}

func postTrybit(ctx context.Context, url string, payload any, out any) ([]byte, error) {
	body, err := common.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Token "+strings.TrimSpace(setting.TrybitApiKey))

	client := &http.Client{Timeout: trybitRequestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, trybitResponseLimit))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return respBody, fmt.Errorf("trybit http status %d body %q", resp.StatusCode, string(respBody))
	}
	if err := common.Unmarshal(respBody, out); err != nil {
		return respBody, err
	}
	return respBody, nil
}

// The callback only proves which invoice it refers to, so both the payment state
// and the invoice/order binding are read back from Trybit with our own api key
// instead of being taken from what the callback claims.
func fetchTrybitInvoiceStatus(ctx context.Context, invoiceId string, orderId string) (string, error) {
	var parsed trybitInvoiceInfoResponse
	respBody, err := postTrybit(ctx, trybitInvoiceInfoURL, &trybitInvoiceInfoRequest{Uuids: []string{invoiceId}}, &parsed)
	if err != nil {
		return "", err
	}
	if parsed.Status != trybitStatusSuccess {
		return "", fmt.Errorf("trybit invoice info status %q body %q", parsed.Status, string(respBody))
	}

	for _, item := range parsed.Result {
		if normalizeTrybitInvoiceId(item.Uuid) != normalizeTrybitInvoiceId(invoiceId) {
			continue
		}
		if item.OrderId != orderId {
			return "", fmt.Errorf("trybit invoice %q carries order id %q not %q", invoiceId, item.OrderId, orderId)
		}
		return item.Status, nil
	}
	return "", fmt.Errorf("trybit invoice %q missing from merchant info body %q", invoiceId, string(respBody))
}

func genTrybitInvoice(ctx context.Context, tradeNo string, payMoney float64, email string) (*trybitInvoice, error) {
	var parsed trybitInvoiceCreateResponse
	respBody, err := postTrybit(ctx, trybitInvoiceCreateURL, &trybitInvoiceCreateRequest{
		ShopId:   strings.TrimSpace(setting.TrybitShopId),
		Amount:   payMoney,
		Currency: trybitInvoiceCurrency,
		OrderId:  tradeNo,
		Email:    email,
	}, &parsed)
	if err != nil {
		return nil, err
	}
	if parsed.Status != trybitStatusSuccess {
		return nil, fmt.Errorf("trybit invoice status %q body %q", parsed.Status, string(respBody))
	}
	if parsed.Result.Uuid == "" || parsed.Result.Link == "" {
		return nil, fmt.Errorf("trybit invoice missing uuid or link body %q", string(respBody))
	}

	expiry, err := time.ParseInLocation(trybitExpiryLayout, parsed.Result.ExpiryDate, time.UTC)
	if err != nil {
		return nil, fmt.Errorf("trybit invoice expiry %q unparsable: %w", parsed.Result.ExpiryDate, err)
	}

	return &trybitInvoice{
		InvoiceId: parsed.Result.Uuid,
		PayLink:   parsed.Result.Link,
		ExpiresAt: expiry.Unix(),
	}, nil
}

func TrybitNotify(c *gin.Context) {
	ctx := c.Request.Context()
	callerIp := c.ClientIP()

	if !isTrybitWebhookEnabled() {
		logger.LogWarn(ctx, fmt.Sprintf("Trybit 回调被拒绝 reason=webhook_disabled path=%q client_ip=%s", c.Request.RequestURI, callerIp))
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	var req trybitNotifyRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.LogWarn(ctx, fmt.Sprintf("Trybit 回调解析失败 client_ip=%s error=%q", callerIp, err.Error()))
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if req.OrderId == "" || req.InvoiceId == "" || req.Token == "" {
		logger.LogWarn(ctx, fmt.Sprintf("Trybit 回调字段缺失 client_ip=%s order_id=%s invoice_id=%s has_token=%t", callerIp, req.OrderId, req.InvoiceId, req.Token != ""))
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if err := verifyTrybitCallbackToken(strings.TrimSpace(setting.TrybitSecretKey), &req); err != nil {
		logger.LogWarn(ctx, fmt.Sprintf("Trybit 回调验签失败 client_ip=%s order_id=%s invoice_id=%s error=%q", callerIp, req.OrderId, req.InvoiceId, err.Error()))
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	LockOrder(req.OrderId)
	defer UnlockOrder(req.OrderId)

	topUp := model.GetTopUpByTradeNo(req.OrderId)
	if topUp == nil {
		logger.LogWarn(ctx, fmt.Sprintf("Trybit 回调对应订单不存在 client_ip=%s order_id=%s invoice_id=%s", callerIp, req.OrderId, req.InvoiceId))
		c.Status(http.StatusOK)
		return
	}
	if topUp.PaymentProvider != model.PaymentProviderTrybit {
		logger.LogWarn(ctx, fmt.Sprintf("Trybit 回调订单支付网关不匹配 client_ip=%s order_id=%s payment_provider=%s", callerIp, req.OrderId, topUp.PaymentProvider))
		c.Status(http.StatusOK)
		return
	}
	// A failed provider ref bind leaves a live, payable invoice attached to an
	// order that never stored its id, so an empty ref falls back to the callback
	// and is validated against the invoice's own order id instead.
	invoiceRef := topUp.ProviderRef
	if invoiceRef == "" {
		invoiceRef = trybitInvoiceIdPrefix + normalizeTrybitInvoiceId(req.InvoiceId)
	} else if normalizeTrybitInvoiceId(invoiceRef) != normalizeTrybitInvoiceId(req.InvoiceId) {
		logger.LogWarn(ctx, fmt.Sprintf("Trybit 回调发票号不匹配 client_ip=%s order_id=%s provider_ref=%s invoice_id=%s", callerIp, req.OrderId, topUp.ProviderRef, req.InvoiceId))
		c.Status(http.StatusOK)
		return
	}

	invoiceStatus, err := fetchTrybitInvoiceStatus(ctx, invoiceRef, req.OrderId)
	if err != nil {
		logger.LogError(ctx, fmt.Sprintf("Trybit 回调查询发票状态失败 client_ip=%s order_id=%s invoice_id=%s error=%q", callerIp, req.OrderId, req.InvoiceId, err.Error()))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if invoiceStatus != trybitInvoiceStatusPaid && invoiceStatus != trybitInvoiceStatusOverpaid {
		expired := topUp.ExpiresAt > 0 && time.Now().Unix() > topUp.ExpiresAt
		if invoiceStatus == trybitInvoiceStatusCanceled || expired {
			logger.LogWarn(ctx, fmt.Sprintf("Trybit 发票已终止，不入账 client_ip=%s order_id=%s invoice_id=%s invoice_status=%s expired=%t", callerIp, req.OrderId, req.InvoiceId, invoiceStatus, expired))
			markTrybitTopUpFailed(ctx, req.OrderId)
			c.Status(http.StatusOK)
			return
		}
		// Crypto confirmation lags the callback, so acknowledging a still-open
		// invoice would burn the only delivery Trybit makes for it.
		logger.LogWarn(ctx, fmt.Sprintf("Trybit 发票未支付，等待重投 client_ip=%s order_id=%s invoice_id=%s invoice_status=%s callback_status=%s amount_crypto=%v currency=%s", callerIp, req.OrderId, req.InvoiceId, invoiceStatus, req.Status, req.AmountCrypto, req.Currency))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	alreadyDone, err := model.RechargeTrybit(req.OrderId, callerIp)
	if err != nil {
		if errors.Is(err, model.ErrTopUpNotFound) || errors.Is(err, model.ErrPaymentMethodMismatch) || errors.Is(err, model.ErrTopUpStatusInvalid) {
			logger.LogWarn(ctx, fmt.Sprintf("Trybit 回调订单不可入账 client_ip=%s order_id=%s error=%q", callerIp, req.OrderId, err.Error()))
			c.Status(http.StatusOK)
			return
		}
		// Anything else may be transient, so fail loudly and let Trybit redeliver.
		logger.LogError(ctx, fmt.Sprintf("Trybit 回调入账失败 client_ip=%s order_id=%s invoice_id=%s error=%q", callerIp, req.OrderId, req.InvoiceId, err.Error()))
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if alreadyDone {
		logger.LogInfo(ctx, fmt.Sprintf("Trybit 回调重复投递，订单已入账 client_ip=%s order_id=%s invoice_id=%s", callerIp, req.OrderId, req.InvoiceId))
	} else {
		logger.LogInfo(ctx, fmt.Sprintf("Trybit 回调入账成功 client_ip=%s order_id=%s invoice_id=%s amount_crypto=%v currency=%s", callerIp, req.OrderId, req.InvoiceId, req.AmountCrypto, req.Currency))
	}
	c.Status(http.StatusOK)
}

func verifyTrybitCallbackToken(secret string, req *trybitNotifyRequest) error {
	claims := &trybitCallbackClaims{}
	if _, err := jwt.ParseWithClaims(req.Token, claims, func(*jwt.Token) (any, error) {
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired(), jwt.WithLeeway(trybitCallbackLeeway)); err != nil {
		return fmt.Errorf("token rejected: %w", err)
	}
	// ParseWithClaims only rejects an expired token; bounding how far ahead exp
	// sits keeps the documented five-minute replay window from being widened by
	// a long-lived token.
	if claims.ExpiresAt == nil || time.Until(claims.ExpiresAt.Time) > trybitCallbackTokenTTL+trybitCallbackLeeway {
		return errors.New("token expiry out of range")
	}
	if normalizeTrybitInvoiceId(claims.Id) == "" {
		return errors.New("token carries no invoice id")
	}
	if normalizeTrybitInvoiceId(claims.Id) != normalizeTrybitInvoiceId(req.InvoiceId) {
		return fmt.Errorf("token invoice id %q does not match callback invoice id %q", claims.Id, req.InvoiceId)
	}
	return nil
}

func normalizeTrybitInvoiceId(invoiceId string) string {
	return strings.TrimPrefix(invoiceId, trybitInvoiceIdPrefix)
}

func getTrybitPayMoney(amount int64, group string) float64 {
	dAmount := decimal.NewFromInt(amount)
	if operation_setting.GetQuotaDisplayType() == operation_setting.QuotaDisplayTypeTokens {
		dAmount = dAmount.Div(decimal.NewFromFloat(common.QuotaPerUnit)).Truncate(0)
	}

	topupGroupRatio := common.GetTopupGroupRatio(group)
	if topupGroupRatio == 0 {
		topupGroupRatio = 1
	}

	discount := 1.0
	if ds, ok := operation_setting.GetPaymentSetting().AmountDiscount[int(amount)]; ok && ds > 0 {
		discount = ds
	}

	return dAmount.
		Mul(decimal.NewFromFloat(setting.TrybitUnitPrice)).
		Mul(decimal.NewFromFloat(topupGroupRatio)).
		Mul(decimal.NewFromFloat(discount)).
		Round(2).
		InexactFloat64()
}

func normalizeTrybitTopUpAmount(amount int64) int64 {
	if operation_setting.GetQuotaDisplayType() != operation_setting.QuotaDisplayTypeTokens {
		return amount
	}

	normalized := decimal.NewFromInt(amount).
		Div(decimal.NewFromFloat(common.QuotaPerUnit)).
		IntPart()
	if normalized < 1 {
		return 1
	}
	return normalized
}
