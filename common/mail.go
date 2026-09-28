package common

import (
	"fmt"
	"html"
	"strings"
)

const (
	mailAccent  = "#d9422d"
	mailInk     = "#1c1b19"
	mailMuted   = "#6f6d67"
	mailPaper   = "#ffffff"
	mailCanvas  = "#f4f2ee"
	mailBorder  = "#e5e2db"
	mailFont    = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
	mailMonoFnt = "'Courier New',Courier,monospace"
)

// MailLayout wraps a letter body into the branded shell. Everything is inline
// and table based because mail clients strip <style>, and the mark is drawn
// with a background colour rather than an <img> because they also block remote
// images by default - the letter has to read with nothing loaded.
func MailLayout(siteURL string, heading string, body string) string {
	site := strings.TrimRight(siteURL, "/")
	return `<!doctype html><html lang="ru"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + html.EscapeString(heading) + `</title></head>` +
		`<body style="margin:0;padding:0;background:` + mailCanvas + `;">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:` + mailCanvas + `;padding:32px 12px;">` +
		`<tr><td align="center">` +
		`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;">` +
		`<tr><td align="center" style="padding-bottom:24px;">` + mailMark(site) + `</td></tr>` +
		`<tr><td style="background:` + mailPaper + `;border:1px solid ` + mailBorder + `;border-radius:14px;padding:32px;">` +
		`<h1 style="margin:0 0 20px;font-family:` + mailFont + `;font-size:21px;line-height:1.3;font-weight:600;color:` + mailInk + `;">` +
		html.EscapeString(heading) + `</h1>` + body + `</td></tr>` +
		`<tr><td style="padding-top:24px;">` + mailFooter(site) + `</td></tr>` +
		`</table></td></tr></table></body></html>`
}

func mailMark(site string) string {
	name := html.EscapeString(SystemName)
	return `<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>` +
		`<td style="background:` + mailAccent + `;border-radius:9px;width:34px;height:34px;text-align:center;` +
		`font-family:` + mailFont + `;font-size:20px;font-weight:700;color:#ffffff;line-height:34px;">a</td>` +
		`<td style="padding-left:10px;font-family:` + mailFont + `;font-size:19px;font-weight:600;color:` + mailInk + `;">` +
		`<a href="` + site + `" style="color:` + mailInk + `;text-decoration:none;">` + name + `</a></td>` +
		`</tr></table>`
}

func mailFooter(site string) string {
	link := func(href string, label string) string {
		return `<a href="` + site + href + `" style="color:` + mailMuted + `;text-decoration:underline;">` + label + `</a>`
	}
	return `<p style="margin:0;font-family:` + mailFont + `;font-size:12.5px;line-height:1.6;color:` + mailMuted + `;text-align:center;">` +
		`Письмо отправлено автоматически, отвечать на него не нужно.<br>` +
		`Вопросы - <a href="mailto:support@akyko.ru" style="color:` + mailMuted + `;text-decoration:underline;">support@akyko.ru</a><br>` +
		link("/legal/terms", "Оферта") + ` &middot; ` + link("/legal/privacy", "Политика конфиденциальности") +
		`</p>`
}

// MailText renders one paragraph of letter copy.
func MailText(text string) string {
	return `<p style="margin:0 0 16px;font-family:` + mailFont + `;font-size:15px;line-height:1.6;color:` + mailInk + `;">` +
		html.EscapeString(text) + `</p>`
}

// MailHint renders the small print that closes a letter.
func MailHint(text string) string {
	return `<p style="margin:16px 0 0;font-family:` + mailFont + `;font-size:13px;line-height:1.6;color:` + mailMuted + `;">` +
		html.EscapeString(text) + `</p>`
}

// MailCode renders the confirmation code as the one element the eye lands on.
// The typography sits on an inner span and the fill is repeated as a bgcolor
// attribute, because Gmail drops the style attribute of the cell itself.
func MailCode(code string) string {
	return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:8px 0;">` +
		`<tr><td align="center" bgcolor="` + mailCanvas + `" style="background-color:` + mailCanvas +
		`;border:1px solid ` + mailBorder + `;border-radius:12px;padding:24px 12px;">` +
		`<span style="font-family:` + mailMonoFnt + `;font-size:40px;font-weight:bold;letter-spacing:12px;` +
		`text-indent:12px;line-height:1.1;color:` + mailInk + `;white-space:nowrap;">` +
		html.EscapeString(code) + `</span></td></tr></table>`
}

// MailValidity states how long the code lives, declined for the given minutes.
func MailValidity(minutes int) string {
	return MailHint(fmt.Sprintf("Код действует %d %s. Если вы ничего не запрашивали, просто проигнорируйте это письмо.",
		minutes, pluralMinutes(minutes)))
}

func pluralMinutes(value int) string {
	if value%100 >= 11 && value%100 <= 14 {
		return "минут"
	}
	switch value % 10 {
	case 1:
		return "минуту"
	case 2, 3, 4:
		return "минуты"
	default:
		return "минут"
	}
}
