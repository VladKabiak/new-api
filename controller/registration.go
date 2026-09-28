package controller

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"

	"github.com/gin-gonic/gin"
)

const (
	registrationCodeInvalid  = "Код неверен или истёк"
	registrationEmailInvalid = "Некорректный адрес электронной почты"
	registrationWeakPassword = "Пароль должен быть от 8 до 20 символов"
)

type registrationRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registrationConfirmRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func registrationEmailRestriction(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return registrationEmailInvalid
	}
	localPart := parts[0]
	domainPart := parts[1]
	if common.EmailDomainRestrictionEnabled {
		allowed := false
		for _, domain := range common.EmailDomainWhitelist {
			if domainPart == domain {
				allowed = true
				break
			}
		}
		if !allowed {
			return "Администратор ограничил список почтовых доменов: этот адрес не разрешён."
		}
	}
	if common.EmailAliasRestrictionEnabled {
		if strings.Contains(localPart, "+") || strings.Contains(localPart, ".") {
			return "Администратор ограничил использование псевдонимов почты: адрес содержит недопустимые символы."
		}
	}
	return ""
}

func usernameFromEmail(email string) (string, error) {
	var builder strings.Builder
	for _, symbol := range strings.ToLower(strings.Split(email, "@")[0]) {
		if (symbol >= 'a' && symbol <= 'z') || (symbol >= '0' && symbol <= '9') || symbol == '_' || symbol == '-' {
			builder.WriteRune(symbol)
		}
	}
	base := builder.String()
	if len(base) > 12 {
		base = base[:12]
	}
	if base == "" {
		base = "user"
	}
	for attempt := 0; attempt < 8; attempt++ {
		candidate := base
		if attempt > 0 {
			candidate = base + strings.ToLower(common.GetRandomString(4))
		}
		exist, err := model.CheckUserExistOrDeleted(candidate, "")
		if err != nil {
			return "", err
		}
		if !exist {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("failed to derive a free username from %s", email)
}

// RequestRegistrationCode starts a password registration: it holds the
// credentials until the address is confirmed with the code sent to it.
func RequestRegistrationCode(c *gin.Context) {
	if !common.RegisterEnabled {
		common.ApiErrorI18n(c, i18n.MsgUserRegisterDisabled)
		return
	}
	if !common.PasswordRegisterEnabled {
		common.ApiErrorI18n(c, i18n.MsgUserPasswordRegisterDisabled)
		return
	}
	var req registrationRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorI18n(c, i18n.MsgInvalidParams)
		return
	}
	email := model.NormalizeEmail(req.Email)
	if err := common.Validate.Var(email, "required,email,max=50"); err != nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": registrationEmailInvalid})
		return
	}
	if message := registrationEmailRestriction(email); message != "" {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": message})
		return
	}
	if len(req.Password) < 8 || len(req.Password) > 20 {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": registrationWeakPassword})
		return
	}
	if model.IsEmailAlreadyTaken(email) {
		common.ApiErrorI18n(c, i18n.MsgUserEmailAlreadyTaken)
		return
	}

	code := common.GenerateEmailCode()
	common.RegisterPendingRegistration(email, req.Password, code)
	subject := fmt.Sprintf("Подтверждение регистрации - %s", common.SystemName)
	content := common.MailLayout(system_setting.ServerAddress, "Подтвердите адрес почты",
		common.MailText(fmt.Sprintf("Этот адрес указали при регистрации в %s. Введите код на странице регистрации, чтобы создать аккаунт.", common.SystemName))+
			common.MailCode(code)+
			common.MailValidity(common.RegistrationValidMinutes))
	if err := common.SendEmail(subject, email, content); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": ""})
}

// ConfirmRegistration consumes the emailed code, creates the account and signs
// the visitor in, so confirmation ends on a ready session.
func ConfirmRegistration(c *gin.Context) {
	var req registrationConfirmRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorI18n(c, i18n.MsgInvalidParams)
		return
	}
	pending, okay := common.TakePendingRegistration(model.NormalizeEmail(req.Email), strings.TrimSpace(req.Code))
	if !okay {
		c.JSON(http.StatusOK, gin.H{"success": false, "message": registrationCodeInvalid})
		return
	}
	if model.IsEmailAlreadyTaken(pending.Email) {
		common.ApiErrorI18n(c, i18n.MsgUserEmailAlreadyTaken)
		return
	}
	username, err := usernameFromEmail(pending.Email)
	if err != nil {
		common.SysLog("registration confirm failed: " + err.Error())
		common.ApiErrorI18n(c, i18n.MsgUserRegisterFailed)
		return
	}
	user := model.User{
		Username:    username,
		Password:    pending.Password,
		DisplayName: username,
		Email:       pending.Email,
		Role:        common.RoleCommonUser,
	}
	if err := user.Insert(0); err != nil {
		if errors.Is(err, model.ErrEmailAlreadyTaken) {
			common.ApiErrorI18n(c, i18n.MsgUserEmailAlreadyTaken)
			return
		}
		common.ApiError(c, err)
		return
	}
	var created model.User
	if err := model.DB.Where("username = ?", username).First(&created).Error; err != nil {
		common.ApiErrorI18n(c, i18n.MsgUserRegisterFailed)
		return
	}
	setupLogin(&created, c)
}
