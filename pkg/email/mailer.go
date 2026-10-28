package email

import (
	"encoding/base64"
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type ClientAuditInfo struct {
	CommonName   string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	IP           string
}

type AlertEvent struct {
	Timestamp time.Time
	Message   string
	Audit     ClientAuditInfo
}

type Mailer struct {
	config Config
}

func NewMailer(cfg Config) *Mailer {
	if cfg.From == "" {
		cfg.From = "gateway@secure.internal.net"
	}
	return &Mailer{config: cfg}
}

func (m *Mailer) SendAlertMail(to string, event AlertEvent) error {
	addr := fmt.Sprintf("%s:%d", m.config.Host, m.config.Port)

	var auth smtp.Auth
	if m.config.Username != "" && m.config.Password != "" {
		auth = smtp.PlainAuth("", m.config.Username, m.config.Password, m.config.Host)
	}

	subject := fmt.Sprintf("CRITICAL ALERT: [%s] Incident Detected", event.Audit.CommonName)
	rawMsg := BuildMultipartMessage(m.config.From, to, subject, event)

	return smtp.SendMail(addr, auth, m.config.From, []string{to}, rawMsg)
}

func BuildMultipartMessage(from, to, subject string, event AlertEvent) []byte {
	boundary := fmt.Sprintf("boundary_%d_alert_gateway", time.Now().UnixNano())

	htmlBody := generateHTMLBody(event)

	logContent := generateIncidentLog(event)
	encodedLog := base64.StdEncoding.EncodeToString([]byte(logContent))

	var formattedBase64 strings.Builder
	for i := 0; i < len(encodedLog); i += 76 {
		end := i + 76
		if end > len(encodedLog) {
			end = len(encodedLog)
		}
		formattedBase64.WriteString(encodedLog[i:end])
		formattedBase64.WriteString("\r\n")
	}

	var msg strings.Builder

	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=UTF-8; name=\"incident_report.log\"\r\n")
	msg.WriteString("Content-Disposition: attachment; filename=\"incident_report.log\"\r\n")
	msg.WriteString("Content-Transfer-Encoding: base64\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(formattedBase64.String())
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return []byte(msg.String())
}

func generateHTMLBody(event AlertEvent) string {
	timeStr := event.Timestamp.Format("2006-01-02 15:04:05 MST")
	validUntil := event.Audit.NotAfter.Format("2006-01-02 15:04:05")

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f4f6f8; margin: 0; padding: 20px; }
        .card { background-color: #ffffff; border-radius: 8px; border: 1px solid #e1e4e8; max-width: 650px; margin: 0 auto; overflow: hidden; }
        .header { background: #b71c1c; color: #ffffff; padding: 20px; text-align: left; }
        .header h1 { margin: 0 0 6px 0; font-size: 20px; }
        .header p { margin: 0; font-size: 13px; opacity: 0.9; }
        .content { padding: 20px; }
        .alert-box { background-color: #fff3e0; border-left: 4px solid #ff9800; padding: 12px 16px; margin-bottom: 20px; font-family: monospace; font-size: 14px; color: #e65100; }
        .table { width: 100%%; border-collapse: collapse; }
        .table th, .table td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eeeeee; font-size: 13px; }
        .table th { background-color: #fafbfc; color: #586069; width: 35%%; }
        .footer { background-color: #fafbfc; padding: 12px 20px; text-align: center; font-size: 12px; color: #6a737d; border-top: 1px solid #e1e4e8; }
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h1>Шлюз безпеки: Сповіщення про інцидент</h1>
            <p>Двостороння автентифікація mTLS підтверджена. Джерело верифіковано.</p>
        </div>
        <div class="content">
            <div class="alert-box">
                %s
            </div>
            <table class="table">
                <tr>
                    <th>Час реєстрації:</th>
                    <td>%s</td>
                </tr>
                <tr>
                    <th>Автентифікований клієнт (CN):</th>
                    <td><strong>%s</strong></td>
                </tr>
                <tr>
                    <th>IP-адреса джерела:</th>
                    <td>%s</td>
                </tr>
                <tr>
                    <th>Серійний номер сертифіката:</th>
                    <td><code>%s</code></td>
                </tr>
                <tr>
                    <th>Дійсність сертифіката до:</th>
                    <td>%s</td>
                </tr>
                <tr>
                    <th>Статус:</th>
                    <td><span style="color: #2e7d32; font-weight: bold;">Zero Trust Validated</span></td>
                </tr>
            </table>
        </div>
        <div class="footer">
            Звіт аудиту прикріплено у файлі <strong>incident_report.log</strong>.
        </div>
    </div>
</body>
</html>`,
		event.Message,
		timeStr,
		event.Audit.CommonName,
		event.Audit.IP,
		event.Audit.SerialNumber,
		validUntil,
	)
}

func generateIncidentLog(event AlertEvent) string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("                      SECURE ALERT GATEWAY INCIDENT REPORT                      \n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("Timestamp:               %s\n", event.Timestamp.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Incident Description:    %s\n", event.Message))
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString("ZERO TRUST CLIENT AUDIT DETAILS\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Client CommonName (CN):  %s\n", event.Audit.CommonName))
	sb.WriteString(fmt.Sprintf("Client Remote Address:   %s\n", event.Audit.IP))
	sb.WriteString(fmt.Sprintf("Certificate Serial No:   %s\n", event.Audit.SerialNumber))
	sb.WriteString(fmt.Sprintf("Valid From:              %s\n", event.Audit.NotBefore.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Valid Until:             %s\n", event.Audit.NotAfter.Format(time.RFC3339)))
	sb.WriteString("Authentication Method:   Mutual TLS (mTLS) - X.509 Client Certificate\n")
	sb.WriteString("Verification Status:     PASSED (Issued by trusted Root CA)\n")
	sb.WriteString("================================================================================\n")
	sb.WriteString("SYSTEM DIAGNOSTICS DUMP:\n")
	sb.WriteString("Node Status:             DEGRADED\n")
	sb.WriteString("Action Required:         Immediate investigation by on-call engineer.\n")
	sb.WriteString("================================================================================\n")
	return sb.String()
}
